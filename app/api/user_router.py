from fastapi import APIRouter, Depends
from fastapi_limiter.depends import RateLimiter
from typing_extensions import Annotated

from app.api.deps import get_current_user, get_user_service
from app.schemas.user import LicenseRequest, TokenData
from app.services.user_service import UserService

user_router = APIRouter()


@user_router.post(
    "/users/license", dependencies=[Depends(RateLimiter(times=2, seconds=5))]
)
async def create_license(
    request: LicenseRequest,
    current_user: Annotated[TokenData, Depends(get_current_user)],
    user_service: UserService = Depends(get_user_service),
):
    return await user_service.create_license(request, current_user.username)


@user_router.get("/users/me", dependencies=[Depends(RateLimiter(times=2, seconds=5))])
async def get_current_user_info(
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    return current_user