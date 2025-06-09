from pydantic.main import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


# TODO: Add fields like MAC, IP, another serials
class Hwid(BaseModel):
    value: str


class TokenData(BaseModel):
    telegram_id: str | None = None
    username: str | None = None
    is_banned: bool
