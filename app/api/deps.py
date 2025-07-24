import logging
import jwt
from fastapi import Depends, HTTPException, status
from sqlmodel import Session
from typing_extensions import Annotated

from app.config import settings
from app.db.database import get_session
from app.repos.user import UserRepository
from app.schemas.user import TokenData
from app.services.auth_service import AuthService
from app.services.user_service import UserService
from app.services.websocket_service import WebSocketService
from app.utils.helpers import oauth2_scheme
from fastapi_limiter.depends import RateLimiter


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> TokenData:
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

        if id is None:
            raise credentials_exception

        token_data = TokenData(id=id, username=username)

        return token_data
    except jwt.InvalidTokenError:
        raise credentials_exception


SessionDep = Annotated[Session, Depends(get_session)]

limiter = RateLimiter(times=2, seconds=5)

def get_auth_service(
    db: SessionDep,
):
    user_repo = get_user_repo(db)
    return AuthService(user_repo)

def get_user_repo(
    db: SessionDep
):
    return UserRepository(db)

def get_user_service(
    db: SessionDep,
):
    user_repo = get_user_repo(db)
    return UserService(user_repo)


def get_websocket_service(
    db: SessionDep,
):
    user_repo = get_user_repo(db)
    return WebSocketService(user_repo)
