import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, StaticPool, create_engine, select

from app.api.deps import get_current_user, limiter
from app.config import settings
from app.db.database import License, User, get_session
from app.main import app
from app.schemas.user import TokenData
from app.utils.helpers import get_password_hash

settings.admin_id = "123"
settings.secret_key = "test_secret"
settings.webhook_url = "https://test-webhook.com/webhook"
settings.bot_token = "test-token"


class DummyRepo:
    def __init__(self, session: Session):
        self.session = session

    def get_by_username(self, username):
        return User(
            id="1",
            username=username,
            password=get_password_hash("1234"),
            is_banned=False,
            is_admin=True,
            license=None,
            hwid="not_linked",
        )

    def create_license(self, user: User, expires_at):
        # add user to session if not exists
        self.session.add(user)
        self.session.commit()

        if user.license:
            self.session.delete(user.license)
            self.session.commit()
            self.session.refresh(user)

        license = License(user_id=user.id, expires_at=expires_at)

        self.session.add(license)
        self.session.commit()
        self.session.refresh(license)

    def get_by_license_id(self, license_id: str) -> User | None:
        user = self.session.exec(
            select(User).where(User.license.id == license_id)
        ).first()

        return user


@pytest.fixture(autouse=True)
def override_repo(monkeypatch, session: Session):
    monkeypatch.setattr("app.api.deps.get_user_repo", lambda db: DummyRepo(session))


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


def test_get_current_user_info(client: TestClient):
    def override_get_current_user():
        return {"username": "testuser", "id": 1}

    app.dependency_overrides[limiter] = lambda: None
    app.dependency_overrides[get_current_user] = override_get_current_user

    response = client.get("/users/me")
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"
    assert response.json()["id"] == 1


def test_create_license(client: TestClient, session: Session):
    payload = {"username": "testuser", "days": 1}

    def override_get_current_user():
        return TokenData(username="testuser", id="1")

    app.dependency_overrides[limiter] = lambda: None
    app.dependency_overrides[get_current_user] = override_get_current_user

    response = client.post("/users/license", json=payload)

    user_from_db = session.exec(select(User).where(User.username == "testuser")).first()

    assert response.status_code == 200
    assert {"message": "license has successfully created"}

    assert user_from_db is not None
    assert user_from_db.license
