from fastapi import APIRouter, Depends
from typing_extensions import Annotated

from app.api.deps import get_current_user, get_user_service, limiter
from app.schemas.user import LicenseRequest, TokenData
from app.services.user_service import UserService

user_router = APIRouter()


@user_router.post("/users/license", dependencies=[Depends(limiter)])
async def create_license(
    request: LicenseRequest,
    current_user: Annotated[TokenData, Depends(get_current_user)],
    user_service: UserService = Depends(get_user_service),
):
    return await user_service.create_license(request, current_user.username)


@user_router.get("/users/me", dependencies=[Depends(limiter)])
async def get_current_user_info(
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    return current_user
