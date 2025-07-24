from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest
from sqlmodel import SQLModel, Session, StaticPool, create_engine, select

from app.db.database import License, User, get_session
from app.main import app
from app.api.deps import get_current_user, limiter
from app.schemas.user import LoginRequest, TokenData
from app.utils.helpers import get_password_hash, verify_expire, verify_password

class DummyRepo:
    def __init__(self, session: Session):
        self.session = session

    def create_user(self, user: User):
        db_user = User.model_validate(user)
        db_user.password = get_password_hash(db_user.password)

        try:
            self.session.add(db_user)
            self.session.commit()
            self.session.refresh(db_user)
        except Exception:
            print("already exists")

    def get_by_username(self, username):
        return User(
            id="1",
            username=username,
            password="$2b$12$jBbGxrDmMNE234r90EwdQeAkjXG6w4nIRNkYBB.x7B4.6Sm4lnY9O",
            is_banned=False,
            is_admin=True,
            license=License(expires_at=datetime.now(timezone.utc) + timedelta(days=1)),
            hwid="not_linked"
        )
    
    def link_hwid(self, user: User, new_hwid):
        if user.hwid == "not_linked":
            user.hwid = new_hwid

            self.session.add(user)
            self.session.commit()
            self.session.refresh(user)
    
    def authenticate_user(self, user: User | None, request: LoginRequest):
        if not user:
            return False
        if not verify_password(request.password, user.password):
            return False
        if user.is_banned:
            return False
        if not user.license:
            return False
        if not verify_expire(user.license.expires_at):
            return False

        # Link HWID if not already linked
        self.link_hwid(user, request.hwid)

        if not user.hwid == request.hwid:
            return False

        return user


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

@pytest.fixture(autouse=True)
def override_repo(monkeypatch, session: Session):
    monkeypatch.setattr("app.api.deps.get_user_repo", lambda db: DummyRepo(session))

def test_create_user(client: TestClient, session: Session):
    payload = {"username": "testuser", "password": "1234", "is_admin": True, "id": "1"}

    def override_get_current_user():
        return TokenData(
            username="testuser",
            id="1"
        )
    
    app.dependency_overrides[limiter] = lambda: None
    app.dependency_overrides[get_current_user] = override_get_current_user
    
    response = client.post("auth/reg", json=payload)

    user_from_db = session.exec(select(User).where(User.username == "testuser")).first()
 
    assert response.status_code == 200

    assert user_from_db is not None
    assert user_from_db.hwid == "not_linked"
    assert {"message": "user has successfully registered"}

def test_login_user(client: TestClient, session: Session):
    payload = {"username": "testuser", "password": "1234", "hwid": "some-hwid"}

    app.dependency_overrides[limiter] = lambda: None

    print(get_password_hash(payload["password"]))

    response = client.post("auth/login", json=payload)

    assert response.status_code == 200
    assert response.json()["access_token"]
    assert response.json()["token_type"]

    user_from_db = session.exec(select(User).where(User.username == "testuser")).first()

    assert user_from_db is not None

    # if hwid was not_linked it will be changed to hwid from the request
    assert user_from_db.hwid == "some-hwid"