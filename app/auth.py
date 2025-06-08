from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import status, Depends, HTTPException
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import InvalidTokenError
from app.database import User
from app.config import settings
from typing import Annotated
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
        telegram_id = payload.get("sub")
        username = payload.get("username")
        is_banned = payload.get("is_banned")

        if telegram_id is None:
            raise credentials_exception

        if is_banned:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="User is banned"
            )

        token_data = TokenData(
            telegram_id=telegram_id, username=username, is_banned=is_banned
        )

        return token_data
    except InvalidTokenError:
        raise credentials_exception


def authenticate_user(user: User | None, data: OAuth2PasswordRequestForm):
    if not user:
        return False
    if not verify_password(data.password, user.password):
        return False
    return user
