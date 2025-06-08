from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session
from typing import Annotated
from app.auth import get_password_hash, authenticate_user, create_access_token
from datetime import timedelta
from app.database import User, get_session
from app.schemas import Token
from contextlib import asynccontextmanager
from sqlmodel import SQLModel, select
from app.database import engine
from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        SQLModel.metadata.create_all(engine)
    except Exception as e:
        print(f"[ERROR] Cannot create a table: {e}")
    yield

    engine.dispose()


app = FastAPI(lifespan=lifespan)


@app.post("/auth/reg")
def create_user(*, session: Session = Depends(get_session), user: User):
    db_user = User.model_validate(user)
    db_user.password = get_password_hash(db_user.password)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


@app.post("/auth/login")
def login_user(
    *,
    session: Session = Depends(get_session),
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = session.exec(select(User).where(User.username == form_data.username)).first()

    logged = authenticate_user(user, form_data)
    if not logged:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": logged.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")
