from pydantic.main import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str
    hwid: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    id: str | None = None
    username: str


class LicenseRequest(BaseModel):
    id: str
    days: int
