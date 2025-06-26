from pydantic.main import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class Hwid(BaseModel):
    value: str


class AdminCreate(BaseModel):
    apassword: str
    id: str
    username: str
    password: str
    is_admin: bool


class TokenData(BaseModel):
    id: str | None = None
    username: str
    is_banned: bool
    hwid: str
    is_admin: bool


class LicenseCreate(BaseModel):
    id: str
    days: int
