import pytest
from fastapi import status
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlmodel import Session
from unittest.mock import patch, MagicMock

from app.database import User
from app.auth import get_password_hash
from app.main import lifespan


class TestCreateUser:
    def test_create_user_success(self, client: TestClient, session: Session):
        user_data = {
            "telegram_id": "123456789",
            "username": "testuser",
            "password": "testpassword123"
        }
        
        response = client.post("/auth/reg", json=user_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["telegram_id"] == user_data["telegram_id"]
        assert data["username"] == user_data["username"]
        assert data["hwid"] == "not_linked"
        assert data["is_banned"] is False
        assert "password" not in data or data["password"] != user_data["password"]
        
        # Verify user was created in database
        db_user = session.get(User, user_data["telegram_id"])
        assert db_user is not None
        assert db_user.username == user_data["username"]

    def test_create_user_duplicate_telegram_id(self, client: TestClient, session: Session):
        # Create first user
        user1_data = {
            "telegram_id": "123456789",
            "username": "testuser1",
            "password": "testpassword123"
        }
        response1 = client.post("/auth/reg", json=user1_data)
        assert response1.status_code == 200
        
        # Try to create second user with same telegram_id
        user2_data = {
            "telegram_id": "123456789",
            "username": "testuser2",
            "password": "testpassword456"
        }
        
        # This should fail due to primary key constraint
        # The endpoint doesn't handle this gracefully, so it raises IntegrityError
        import pytest
        from sqlalchemy.exc import IntegrityError
        
        with pytest.raises(IntegrityError):
            client.post("/auth/reg", json=user2_data)


class TestLoginUser:
    def test_login_success(self, client: TestClient, session: Session):
        # First create a user
        password = "testpassword123"
        user = User(
            telegram_id="123456789",
            username="testuser",
            password=get_password_hash(password),
            hwid="not_linked",
            is_banned=False
        )
        session.add(user)
        session.commit()
        
        # Now try to login
        login_data = {
            "username": "testuser",
            "password": password
        }
        
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_username(self, client: TestClient, session: Session):
        # Create a user
        user = User(
            telegram_id="123456789",
            username="testuser",
            password=get_password_hash("testpassword123"),
        )
        session.add(user)
        session.commit()
        
        # Try to login with wrong username
        login_data = {
            "username": "wronguser",
            "password": "testpassword123"
        }
        
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == 401
        assert response.json()["detail"] == "Incorrect username or password"

    def test_login_wrong_password(self, client: TestClient, session: Session):
        # Create a user
        user = User(
            telegram_id="123456789",
            username="testuser",
            password=get_password_hash("testpassword123"),
        )
        session.add(user)
        session.commit()
        
        # Try to login with wrong password
        login_data = {
            "username": "testuser",
            "password": "wrongpassword"
        }
        
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == 401
        assert response.json()["detail"] == "Incorrect username or password"

    def test_login_nonexistent_user(self, client: TestClient):
        login_data = {
            "username": "nonexistent",
            "password": "somepassword"
        }
        
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == 401
        assert response.json()["detail"] == "Incorrect username or password"


class TestReadUsersMe:
    @pytest.mark.anyio
    async def test_read_users_me_success(self, async_client: AsyncClient, session: Session):
        # Create a user
        password = "testpassword123"
        user = User(
            telegram_id="123456789",
            username="testuser",
            password=get_password_hash(password),
            hwid="test-hwid-123",
            is_banned=False
        )
        session.add(user)
        session.commit()
        
        # Login to get token
        login_data = {
            "username": "testuser",
            "password": password
        }
        login_response = await async_client.post("/auth/login", data=login_data)
        token = login_response.json()["access_token"]
        
        # Call the protected endpoint
        headers = {"Authorization": f"Bearer {token}"}
        response = await async_client.get("/users/me/", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["telegram_id"] == "123456789"
        assert data["username"] == "testuser"
        assert data["hwid"] == "test-hwid-123"
        assert data["is_banned"] is False

    @pytest.mark.anyio
    async def test_read_users_me_no_token(self, async_client: AsyncClient):
        response = await async_client.get("/users/me/")
        
        assert response.status_code == 401
        assert response.json()["detail"] == "Not authenticated"

    @pytest.mark.anyio
    async def test_read_users_me_invalid_token(self, async_client: AsyncClient):
        headers = {"Authorization": "Bearer invalid-token"}
        response = await async_client.get("/users/me/", headers=headers)
        
        assert response.status_code == 401
        assert response.json()["detail"] == "Could not validate credentials"

    @pytest.mark.anyio
    async def test_read_users_me_banned_user(self, async_client: AsyncClient, session: Session):
        # Create a banned user
        password = "testpassword123"
        user = User(
            telegram_id="123456789",
            username="banneduser",
            password=get_password_hash(password),
            hwid="test-hwid-123",
            is_banned=True
        )
        session.add(user)
        session.commit()
        
        # Login to get token
        login_data = {
            "username": "banneduser",
            "password": password
        }
        login_response = await async_client.post("/auth/login", data=login_data)
        token = login_response.json()["access_token"]
        
        # Try to access protected endpoint with banned user token
        headers = {"Authorization": f"Bearer {token}"}
        response = await async_client.get("/users/me/", headers=headers)
        
        assert response.status_code == 400
        assert response.json()["detail"] == "User is banned"


class TestLinkHwid:
    @pytest.mark.anyio
    async def test_link_hwid_success(self, async_client: AsyncClient, session: Session):
        # Create a user with default hwid
        password = "testpassword123"
        user = User(
            telegram_id="123456789",
            username="testuser",
            password=get_password_hash(password),
            hwid="not_linked",
            is_banned=False
        )
        session.add(user)
        session.commit()
        
        # Login to get token
        login_data = {
            "username": "testuser",
            "password": password
        }
        login_response = await async_client.post("/auth/login", data=login_data)
        token = login_response.json()["access_token"]
        
        # Link hwid
        hwid_data = {"value": "new-hwid-12345"}
        headers = {"Authorization": f"Bearer {token}"}
        response = await async_client.patch("/users/hwid", json=hwid_data, headers=headers)
        
        assert response.status_code == 200
        assert response.json()["message"] == "hwid has been successfully linked"
        
        # Verify hwid was updated in database
        session.refresh(user)
        assert user.hwid == "new-hwid-12345"

    @pytest.mark.anyio
    async def test_link_hwid_already_linked(self, async_client: AsyncClient, session: Session):
        # Create a user with already linked hwid
        password = "testpassword123"
        user = User(
            telegram_id="123456789",
            username="testuser",
            password=get_password_hash(password),
            hwid="existing-hwid-123",
            is_banned=False
        )
        session.add(user)
        session.commit()
        
        # Login to get token
        login_data = {
            "username": "testuser",
            "password": password
        }
        login_response = await async_client.post("/auth/login", data=login_data)
        token = login_response.json()["access_token"]
        
        # Try to link hwid again
        hwid_data = {"value": "new-hwid-12345"}
        headers = {"Authorization": f"Bearer {token}"}
        response = await async_client.patch("/users/hwid", json=hwid_data, headers=headers)
        
        assert response.status_code == 409
        assert response.json()["detail"] == "hwid's already linked"

    @pytest.mark.anyio
    async def test_link_hwid_no_token(self, async_client: AsyncClient):
        hwid_data = {"value": "new-hwid-12345"}
        response = await async_client.patch("/users/hwid", json=hwid_data)
        
        assert response.status_code == 401
        assert response.json()["detail"] == "Not authenticated"

    @pytest.mark.anyio
    async def test_link_hwid_invalid_token(self, async_client: AsyncClient):
        hwid_data = {"value": "new-hwid-12345"}
        headers = {"Authorization": "Bearer invalid-token"}
        response = await async_client.patch("/users/hwid", json=hwid_data, headers=headers)
        
        assert response.status_code == 401
        assert response.json()["detail"] == "Could not validate credentials"

    @pytest.mark.anyio
    async def test_link_hwid_banned_user(self, async_client: AsyncClient, session: Session):
        # Create a banned user
        password = "testpassword123"
        user = User(
            telegram_id="123456789",
            username="banneduser",
            password=get_password_hash(password),
            hwid="not_linked",
            is_banned=True
        )
        session.add(user)
        session.commit()
        
        # Login to get token
        login_data = {
            "username": "banneduser",
            "password": password
        }
        login_response = await async_client.post("/auth/login", data=login_data)
        token = login_response.json()["access_token"]
        
        # Try to link hwid with banned user token
        hwid_data = {"value": "new-hwid-12345"}
        headers = {"Authorization": f"Bearer {token}"}
        response = await async_client.patch("/users/hwid", json=hwid_data, headers=headers)
        
        assert response.status_code == 400
        assert response.json()["detail"] == "User is banned"

    @pytest.mark.anyio
    async def test_link_hwid_user_not_found_in_db(self, async_client: AsyncClient, session: Session):
        # This test simulates a scenario where token is valid but user doesn't exist in DB
        # This shouldn't happen in normal flow, but we test edge case
        from app.auth import create_access_token
        from datetime import timedelta
        
        # Create token for non-existent user
        access_token = create_access_token(
            data={
                "sub": "999999999",  # Non-existent telegram_id
                "username": "nonexistent",
                "hwid": "not_linked",
                "is_banned": False,
            },
            expires_delta=timedelta(minutes=30)
        )
        
        hwid_data = {"value": "new-hwid-12345"}
        headers = {"Authorization": f"Bearer {access_token}"}
        response = await async_client.patch("/users/hwid", json=hwid_data, headers=headers)
        
        assert response.status_code == 404
        assert response.json()["detail"] == "User not found"


class TestLifespan:
    @pytest.mark.anyio
    async def test_lifespan_success(self):
        app_mock = MagicMock()
        
        with patch('app.main.SQLModel.metadata.create_all') as mock_create_all, \
             patch('app.main.engine.dispose') as mock_dispose:
            
            async with lifespan(app_mock):
                # Test that create_all was called during startup
                mock_create_all.assert_called_once()
                
            # Test that dispose was called during shutdown
            mock_dispose.assert_called_once()

    @pytest.mark.anyio
    async def test_lifespan_exception_handling(self):
        app_mock = MagicMock()
        
        with patch('app.main.SQLModel.metadata.create_all') as mock_create_all, \
             patch('app.main.engine.dispose') as mock_dispose, \
             patch('builtins.print') as mock_print:
            
            # Make create_all raise an exception
            mock_create_all.side_effect = Exception("Database connection failed")
            
            async with lifespan(app_mock):
                # Test that the exception was caught and logged
                mock_print.assert_called_once_with("[ERROR] Cannot create a table: Database connection failed")
                
            # Test that dispose was still called during shutdown
            mock_dispose.assert_called_once()