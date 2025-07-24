from datetime import timedelta

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, StaticPool, create_engine

from app.api.deps import get_current_user
from app.db.database import get_session
from app.main import app
from app.utils.helpers import create_access_token


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


@pytest.mark.anyio
async def test_get_current_user():
    token = create_access_token({"username": "testuser", "sub": "1"})

    current_user = await get_current_user(token)

    assert current_user.id == "1"
    assert current_user.username == "testuser"


@pytest.mark.anyio
async def test_get_current_user_invalid_token():
    token = "INVALID_TOKEN"

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(token)

    assert exc_info.value.status_code == 401


@pytest.mark.anyio
async def test_get_current_user_expired_token():
    token = create_access_token(
        {"username": "testuser", "id": "1"}, timedelta(minutes=-5)
    )

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(token)

    assert exc_info.value.status_code == 401
