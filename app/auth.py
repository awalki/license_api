from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext

from app.config import settings
from app.database import User
from app.schemas import TokenData

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

        if id is None:
            raise credentials_exception

        if is_banned:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is banned"
            )

        token_data = TokenData(
            id=id, username=username, is_banned=is_banned, hwid=hwid
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
    if user.is_banned:
        return False
    if not user.license:
        return False
    if not verify_expire(user.license.expires_at):
        return False

    return user
