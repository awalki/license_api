from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi_limiter.depends import RateLimiter

from app.api.deps import get_auth_service, get_current_user
from app.db.database import User
from app.schemas.user import LoginRequest, TokenData
from app.services.auth_service import AuthService

auth_router = APIRouter()

auth_router.middleware_stack


@auth_router.post(
    "/auth/login", dependencies=[Depends(RateLimiter(times=2, seconds=5))]
)
async def login_user(
    request: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    return await auth_service.login(request)


@auth_router.post("/auth/reg", dependencies=[Depends(RateLimiter(times=2, seconds=5))])
async def create_user(
    request: User,
    current_user: Annotated[TokenData, Depends(get_current_user)],
    auth_service: AuthService = Depends(get_auth_service),
):
    return await auth_service.register(request, current_user)
