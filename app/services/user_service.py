from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status

from app.repos.user import UserRepository
from app.schemas.user import LicenseRequest


class UserService:
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def create_license(self, request: LicenseRequest, username: str) -> dict:
        authorized = self.user_repo.get_by_username(username)

        if not authorized.is_admin:
            raise HTTPException(status_code=403, detail="Not authorized")

        user = self.user_repo.get_by_username(request.username)

        expires_at = datetime.now(timezone.utc) + timedelta(days=request.days)

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        try:
            self.user_repo.create_license(user, expires_at)

            return {"message": "license has successfully created"}
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="unexpected error"
            )
