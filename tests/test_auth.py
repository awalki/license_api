import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import jwt
from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    get_current_user,
    authenticate_user,
    pwd_context
)
from app.database import User
from app.schemas import TokenData
from app.config import settings


class TestPasswordFunctions:
    def test_get_password_hash(self):
        password = "testpassword123"
        hashed = get_password_hash(password)
        
        assert hashed != password
        assert isinstance(hashed, str)
        assert len(hashed) > 0
        assert hashed.startswith("$2b$")  # bcrypt hash prefix

    def test_verify_password_correct(self):
        password = "testpassword123"
        hashed = get_password_hash(password)
        
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        password = "testpassword123"
        wrong_password = "wrongpassword"
        hashed = get_password_hash(password)
        
        assert verify_password(wrong_password, hashed) is False

    def test_verify_password_empty_strings(self):
        # Empty passwords cannot be verified against empty hash
        # bcrypt will raise an exception for invalid hash format
        with pytest.raises(ValueError):
            verify_password("", "")

    def test_password_hash_consistency(self):
        password = "testpassword123"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        
        # Hashes should be different due to salt
        assert hash1 != hash2
        # But both should verify correctly
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True


class TestCreateAccessToken:
    def test_create_access_token_default_expiry(self):
        data = {"sub": "123456789", "username": "testuser"}
        token = create_access_token(data)
        
        assert isinstance(token, str)
        # Decode to verify structure
        decoded = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        assert decoded["sub"] == "123456789"
        assert decoded["username"] == "testuser"
        assert "exp" in decoded

    def test_create_access_token_custom_expiry(self):
        data = {"sub": "123456789", "username": "testuser"}
        expires_delta = timedelta(minutes=60)
        token = create_access_token(data, expires_delta)
        
        decoded = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        exp_time = datetime.fromtimestamp(decoded["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        
        # Should expire in approximately 60 minutes
        time_diff = exp_time - now
        assert 3590 <= time_diff.total_seconds() <= 3610  # Allow some seconds tolerance

    def test_create_access_token_with_all_fields(self):
        data = {
            "sub": "123456789",
            "username": "testuser",
            "hwid": "test-hwid",
            "is_banned": False
        }
        token = create_access_token(data)
        
        decoded = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        assert decoded["sub"] == "123456789"
        assert decoded["username"] == "testuser"
        assert decoded["hwid"] == "test-hwid"
        assert decoded["is_banned"] is False

    def test_create_access_token_empty_data(self):
        data = {}
        token = create_access_token(data)
        
        decoded = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        assert "exp" in decoded
        assert len(decoded) == 1  # Only exp field


class TestGetCurrentUser:
    @pytest.mark.anyio
    async def test_get_current_user_valid_token(self):
        # Create a valid token
        data = {
            "sub": "123456789",
            "username": "testuser",
            "hwid": "test-hwid",
            "is_banned": False
        }
        token = create_access_token(data)
        
        result = await get_current_user(token)
        
        assert isinstance(result, TokenData)
        assert result.telegram_id == "123456789"
        assert result.username == "testuser"
        assert result.hwid == "test-hwid"
        assert result.is_banned is False

    @pytest.mark.anyio
    async def test_get_current_user_invalid_token(self):
        invalid_token = "invalid.token.here"
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(invalid_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Could not validate credentials"

    @pytest.mark.anyio
    async def test_get_current_user_expired_token(self):
        # Create an expired token
        data = {"sub": "123456789", "username": "testuser"}
        expired_token = create_access_token(data, timedelta(seconds=-1))
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(expired_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Could not validate credentials"

    @pytest.mark.anyio
    async def test_get_current_user_no_sub_in_token(self):
        # Create token without 'sub' field
        data = {"username": "testuser", "hwid": "test-hwid"}
        token = jwt.encode(data, settings.secret_key, algorithm=settings.algorithm)
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Could not validate credentials"

    @pytest.mark.anyio
    async def test_get_current_user_banned_user(self):
        # Create token for banned user
        data = {
            "sub": "123456789",
            "username": "banneduser",
            "hwid": "test-hwid",
            "is_banned": True
        }
        token = create_access_token(data)
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(token)
        
        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert exc_info.value.detail == "User is banned"

    @pytest.mark.anyio
    async def test_get_current_user_wrong_algorithm(self):
        # Create token with wrong algorithm
        data = {"sub": "123456789", "username": "testuser"}
        wrong_token = jwt.encode(data, settings.secret_key, algorithm="HS512")
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(wrong_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Could not validate credentials"

    @pytest.mark.anyio
    async def test_get_current_user_wrong_secret(self):
        # Create token with wrong secret
        data = {"sub": "123456789", "username": "testuser"}
        wrong_token = jwt.encode(data, "wrong-secret", algorithm=settings.algorithm)
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(wrong_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Could not validate credentials"

    @pytest.mark.anyio
    async def test_get_current_user_malformed_token(self):
        malformed_token = "not.a.valid.jwt.token"
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(malformed_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Could not validate credentials"


class TestAuthenticateUser:
    def test_authenticate_user_success(self):
        password = "testpassword123"
        user = User(
            telegram_id="123456789",
            username="testuser",
            password=get_password_hash(password),
            hwid="not_linked",
            is_banned=False
        )
        
        # Mock OAuth2PasswordRequestForm
        form_data = OAuth2PasswordRequestForm(
            username="testuser",
            password=password
        )
        
        result = authenticate_user(user, form_data)
        
        assert result == user

    def test_authenticate_user_wrong_password(self):
        password = "testpassword123"
        user = User(
            telegram_id="123456789",
            username="testuser",
            password=get_password_hash(password),
            hwid="not_linked",
            is_banned=False
        )
        
        form_data = OAuth2PasswordRequestForm(
            username="testuser",
            password="wrongpassword"
        )
        
        result = authenticate_user(user, form_data)
        
        assert result is False

    def test_authenticate_user_none_user(self):
        form_data = OAuth2PasswordRequestForm(
            username="testuser",
            password="testpassword123"
        )
        
        result = authenticate_user(None, form_data)
        
        assert result is False

    def test_authenticate_user_empty_password(self):
        user = User(
            telegram_id="123456789",
            username="testuser",
            password=get_password_hash("testpassword123"),
            hwid="not_linked",
            is_banned=False
        )
        
        form_data = OAuth2PasswordRequestForm(
            username="testuser",
            password=""
        )
        
        result = authenticate_user(user, form_data)
        
        assert result is False

    def test_authenticate_user_with_banned_user(self):
        # Test that authentication still works for banned users
        # (ban check happens in get_current_user, not authenticate_user)
        password = "testpassword123"
        user = User(
            telegram_id="123456789",
            username="banneduser",
            password=get_password_hash(password),
            hwid="not_linked",
            is_banned=True
        )
        
        form_data = OAuth2PasswordRequestForm(
            username="banneduser",
            password=password
        )
        
        result = authenticate_user(user, form_data)
        
        assert result == user


class TestPasswordContextIntegration:
    def test_pwd_context_schemes(self):
        # Verify bcrypt is being used
        assert "bcrypt" in pwd_context.schemes()

    def test_pwd_context_verify_method(self):
        password = "testpassword123"
        hashed = pwd_context.hash(password)
        
        assert pwd_context.verify(password, hashed) is True
        assert pwd_context.verify("wrongpassword", hashed) is False

    def test_pwd_context_hash_method(self):
        password = "testpassword123"
        hashed = pwd_context.hash(password)
        
        assert isinstance(hashed, str)
        assert hashed != password
        assert len(hashed) > 0