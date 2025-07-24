from datetime import timedelta

from fastapi import HTTPException, status

from app.config import settings
from app.db.database import User
from app.repos.user import UserRepository
from app.schemas.user import LoginRequest, Token, TokenData
from app.utils.helpers import create_access_token


# TODO: on successful login, on successfull register callbacks
class AuthService:
    def __init__(self, user_repo: UserRepository) -> None:
        self.user_repo = user_repo

    async def login(self, request: LoginRequest) -> Token:
        user = self.user_repo.get_by_username(request.username)

        logged = self.user_repo.authenticate_user(user, request)

        if not logged:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )

        access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
        access_token = create_access_token(
            data={
                "sub": logged.id,
                "username": logged.username,
            },
            expires_delta=access_token_expires,
        )
        return Token(access_token=access_token, token_type="bearer")

    async def register(self, request: User, username: str):
        authorized = self.user_repo.get_by_username(username)

        if not authorized.is_admin:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized"
            )

        self.user_repo.create_user(request)

        return {"message": "user has successfully registered"}
