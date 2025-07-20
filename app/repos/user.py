from fastapi.logger import logger
from sqlmodel import Session, select

from app.db.database import License, User
from app.schemas.user import LoginRequest
from app.utils.helpers import get_password_hash, verify_expire, verify_password


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_username(self, username: str) -> User | None:
        user = self.db.exec(select(User).where(User.username == username)).first()

        return user
    
    def get_all_users(self):
        users = self.db.exec(select(User)).all()
        
        return users

    def get_by_license_id(self, license_id: str) -> User | None:
        user = self.db.exec(select(User).where(User.license.id == license_id)).first()

        return user

    def create_user(self, user: User):
        db_user = User.model_validate(user)
        db_user.password = get_password_hash(db_user.password)

        try:
            self.db.add(db_user)
            self.db.commit()
            self.db.refresh(db_user)
        except Exception:
            logger.error("User with this username already exists")

    def link_hwid(self, user: User, new_hwid):
        if user.hwid == "not_linked":
            user.hwid = new_hwid

            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)

    def create_license(self, user: User, expires_at):
        if user.license:
            self.db.delete(user.license)
            self.db.commit()
            self.db.refresh(user)

        license = License(user_id=user.id, expires_at=expires_at)

        self.db.add(license)
        self.db.commit()
        self.db.refresh(license)

    def authenticate_user(self, user: User | None, request: LoginRequest):
        if not user:
            return False
        if not verify_password(request.password, user.password):
            return False
        if user.is_banned:
            return False
        if not user.license:
            return False
        if not verify_expire(user.license.expires_at):
            return False

        # Link HWID if not already linked
        self.link_hwid(user, request.hwid)

        if not user.hwid == request.hwid:
            return False

        return user
