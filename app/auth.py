from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi.routing import APIRouter
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from sqlmodel import select

from app.config import settings
from app.database import SessionDep, User
from app.schemas import Token, TokenData

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key, algorithm=settings.algorithm
    )
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm]
        )
        id = payload.get("sub")
        username = payload.get("username")
        is_banned = payload.get("is_banned")
        hwid = payload.get("hwid")
        is_admin = payload.get("is_admin")

        if id is None:
            raise credentials_exception

        if is_banned:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is banned"
            )

        token_data = TokenData(
            id=id, username=username, is_banned=is_banned, hwid=hwid, is_admin=is_admin
        )

        return token_data
    except InvalidTokenError:
        raise credentials_exception


def verify_expire(time: datetime):
    if time.tzinfo is None:
        time = time.replace(tzinfo=timezone.utc)
    return time > datetime.now(timezone.utc)


def authenticate_user(user: User | None, data: OAuth2PasswordRequestForm):
    if not user:
        return False
    if not verify_password(data.password, user.password):
        return False
    if user.is_admin:
        return user
    if user.is_banned:
        return False
    if not user.license:
        return False
    if not verify_expire(user.license.expires_at):
        return False

    return user


auth_router = APIRouter()


@auth_router.post("/auth/login")
def login_user(
    *,
    session: SessionDep,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = session.exec(select(User).where(User.username == form_data.username)).first()

    logged = authenticate_user(user, form_data)
    if not logged:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password, perhaps you don't have an activated license or your account is banned",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={
            "sub": logged.id,
            "username": logged.username,
            "hwid": logged.hwid,
            "is_banned": logged.is_banned,
            "is_admin": logged.is_admin,
        },
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")
