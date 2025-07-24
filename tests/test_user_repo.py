from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, StaticPool, create_engine, select

from app.api.deps import get_user_repo
from app.db.database import User, get_session
from app.main import app
from app.schemas.user import LoginRequest


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override

    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def test_user_repo(session: Session):
    user_repo = get_user_repo(session)

    user_repo.create_user(
        User(
            username="testuser",
            id="1",
            hwid="not_linked",
            is_admin=False,
            password="12345",
        )
    )

    user_from_db = session.exec(select(User).where(User.username == "testuser")).first()

    assert user_from_db is not None
    assert user_from_db.username == "testuser"

    user_repo = get_user_repo(session)
    user = user_repo.get_by_username("testuser")

    assert user is not None
    assert user.username == "testuser"

    user_repo.link_hwid(user, "new_hwid")

    assert user.hwid == "new_hwid"

    user_repo.create_license(user, datetime.now(timezone.utc) + timedelta(days=5))

    assert user.license is not None
    old_license = user.license.expires_at

    user_repo.create_license(user, datetime.now(timezone.utc) + timedelta(days=10))
    new_license = user.license.expires_at

    assert old_license != new_license

    users = user_repo.get_all_users()

    assert users

    login_request = LoginRequest(username="testuser", password="12345", hwid="new_hwid")

    is_auth = user_repo.authenticate_user(user, login_request)

    assert is_auth

    login_request = LoginRequest(
        username="testuser", password="123456", hwid="new_hwid"
    )

    is_auth = user_repo.authenticate_user(user, login_request)

    assert not is_auth

    login_request = LoginRequest(
        username="testuser", password="12345", hwid="invalid_hwid"
    )

    is_auth = user_repo.authenticate_user(user, login_request)

    assert not is_auth

    unknown_user = user_repo.get_by_username("unknown_user")

    login_request = LoginRequest(
        username="unknown_username", password="12345", hwid="new_hwid"
    )

    is_auth = user_repo.authenticate_user(unknown_user, login_request)

    assert not is_auth

    user.license.expires_at = datetime.now(timezone.utc) + timedelta(minutes=-5)

    is_auth = user_repo.authenticate_user(user, login_request)

    assert not is_auth

    login_request = LoginRequest(
        username="unknown_username", password="12345", hwid="new_hwid"
    )

    user.license = None

    is_auth = user_repo.authenticate_user(user, login_request)

    assert not is_auth

    login_request = LoginRequest(
        username="unknown_username", password="12345", hwid="new_hwid"
    )

    user.is_banned = True
    is_auth = user_repo.authenticate_user(user, login_request)

    assert not is_auth

    # already exists
    with pytest.raises(HTTPException) as exc_info:
        user_repo.create_user(
            User(
                username="testuser",
                id="1",
                hwid="not_linked",
                is_admin=False,
                password="12345",
            )
        )

    assert exc_info.value.status_code == 409
