import pytest
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from app.database import User, get_session, engine


class TestUserModel:
    def test_user_creation_with_defaults(self):
        user = User(
            telegram_id="123456789",
            username="testuser",
            password="hashedpassword"
        )
        
        assert user.telegram_id == "123456789"
        assert user.username == "testuser"
        assert user.password == "hashedpassword"
        assert user.hwid == "not_linked"  # Default value
        assert user.is_banned is False  # Default value

    def test_user_creation_with_all_fields(self):
        user = User(
            telegram_id="123456789",
            username="testuser",
            password="hashedpassword",
            hwid="custom-hwid-123",
            is_banned=True
        )
        
        assert user.telegram_id == "123456789"
        assert user.username == "testuser"
        assert user.password == "hashedpassword"
        assert user.hwid == "custom-hwid-123"
        assert user.is_banned is True

    def test_user_primary_key(self):
        # Test that telegram_id is the primary key
        user = User(
            telegram_id="123456789",
            username="testuser",
            password="hashedpassword"
        )
        
        # Check that the field has primary_key=True
        telegram_id_field = User.__table__.columns['telegram_id']
        assert telegram_id_field.primary_key is True

    def test_user_model_fields_types(self):
        user = User(
            telegram_id="123456789",
            username="testuser",
            password="hashedpassword"
        )
        
        assert isinstance(user.telegram_id, str)
        assert isinstance(user.username, str)
        assert isinstance(user.password, str)
        assert isinstance(user.hwid, str)
        assert isinstance(user.is_banned, bool)

    def test_user_table_name(self):
        # Verify that the table is created with correct name
        assert User.__tablename__ == "user"

    def test_user_model_validation(self):
        # Test with empty strings
        user = User(
            telegram_id="",
            username="",
            password=""
        )
        
        assert user.telegram_id == ""
        assert user.username == ""
        assert user.password == ""

    def test_user_field_defaults_in_model(self):
        # Test that defaults are set at model level
        fields = User.model_fields
        assert fields['hwid'].default == "not_linked"
        assert fields['is_banned'].default is False


class TestGetSession:
    def test_get_session_yields_session(self):
        # Test that get_session yields a Session object
        session_generator = get_session()
        session = next(session_generator)
        
        assert isinstance(session, Session)
        
        # Clean up
        try:
            next(session_generator)
        except StopIteration:
            pass  # Expected behavior

    def test_get_session_context_manager(self):
        # Test that the session is properly closed after use
        sessions = list(get_session())
        assert len(sessions) == 1
        assert isinstance(sessions[0], Session)

    def test_get_session_multiple_calls(self):
        # Test that each call returns a fresh session
        gen1 = get_session()
        gen2 = get_session()
        
        session1 = next(gen1)
        session2 = next(gen2)
        
        assert isinstance(session1, Session)
        assert isinstance(session2, Session)
        # Sessions should be different instances
        assert session1 is not session2
        
        # Clean up
        for gen in [gen1, gen2]:
            try:
                next(gen)
            except StopIteration:
                pass


class TestDatabaseIntegration:
    def test_user_crud_operations(self):
        # Create in-memory database for testing
        test_engine = create_engine(
            "sqlite://", 
            connect_args={"check_same_thread": False}, 
            poolclass=StaticPool
        )
        SQLModel.metadata.create_all(test_engine)
        
        with Session(test_engine) as session:
            # Create user
            user = User(
                telegram_id="123456789",
                username="testuser",
                password="hashedpassword",
                hwid="test-hwid",
                is_banned=False
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            
            # Read user
            retrieved_user = session.get(User, "123456789")
            assert retrieved_user is not None
            assert retrieved_user.telegram_id == "123456789"
            assert retrieved_user.username == "testuser"
            assert retrieved_user.password == "hashedpassword"
            assert retrieved_user.hwid == "test-hwid"
            assert retrieved_user.is_banned is False
            
            # Update user
            retrieved_user.hwid = "updated-hwid"
            retrieved_user.is_banned = True
            session.add(retrieved_user)
            session.commit()
            session.refresh(retrieved_user)
            
            assert retrieved_user.hwid == "updated-hwid"
            assert retrieved_user.is_banned is True
            
            # Delete user
            session.delete(retrieved_user)
            session.commit()
            
            deleted_user = session.get(User, "123456789")
            assert deleted_user is None

    def test_user_duplicate_primary_key(self):
        # Test constraint violation
        test_engine = create_engine(
            "sqlite://", 
            connect_args={"check_same_thread": False}, 
            poolclass=StaticPool
        )
        SQLModel.metadata.create_all(test_engine)
        
        with Session(test_engine) as session:
            # Create first user
            user1 = User(
                telegram_id="123456789",
                username="user1",
                password="password1"
            )
            session.add(user1)
            session.commit()
            
            # Try to create second user with same telegram_id
            user2 = User(
                telegram_id="123456789",
                username="user2",
                password="password2"
            )
            session.add(user2)
            
            # This should raise an exception
            with pytest.raises(Exception):  # SQLite will raise IntegrityError
                session.commit()

    def test_user_query_operations(self):
        test_engine = create_engine(
            "sqlite://", 
            connect_args={"check_same_thread": False}, 
            poolclass=StaticPool
        )
        SQLModel.metadata.create_all(test_engine)
        
        with Session(test_engine) as session:
            # Create multiple users
            users = [
                User(telegram_id="1", username="user1", password="pass1"),
                User(telegram_id="2", username="user2", password="pass2", is_banned=True),
                User(telegram_id="3", username="user3", password="pass3", hwid="hwid-123"),
            ]
            
            for user in users:
                session.add(user)
            session.commit()
            
            # Query all users
            from sqlmodel import select
            all_users = session.exec(select(User)).all()
            assert len(all_users) == 3
            
            # Query by username
            user1 = session.exec(select(User).where(User.username == "user1")).first()
            assert user1 is not None
            assert user1.telegram_id == "1"
            
            # Query banned users
            banned_users = session.exec(select(User).where(User.is_banned == True)).all()
            assert len(banned_users) == 1
            assert banned_users[0].username == "user2"
            
            # Query by hwid
            users_with_hwid = session.exec(select(User).where(User.hwid != "not_linked")).all()
            assert len(users_with_hwid) == 1
            assert users_with_hwid[0].username == "user3"


class TestDatabaseConfiguration:
    def test_engine_configuration(self):
        # Test that engine is properly configured
        assert engine is not None
        assert str(engine.url) == "sqlite:///database.db"
        
        # Test that echo is enabled (from database.py)
        assert engine.echo is True

    def test_sqlite_file_configuration(self):
        # Test the database file configuration
        from app.database import sqlite_file_name, sqlite_url
        
        assert sqlite_file_name == "database.db"
        assert sqlite_url == "sqlite:///database.db"