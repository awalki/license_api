from datetime import datetime
from typing import Annotated, Optional

from fastapi import Depends
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
engine = create_engine(sqlite_url, echo=True)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


class User(SQLModel, table=True):
    id: str = Field(primary_key=True)
    username: str
    password: str
    hwid: str = Field(default="not_linked")
    is_banned: bool = Field(default=False)
    is_admin: bool = Field(default=False)

    license: Optional["License"] = Relationship(back_populates="user")


class License(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: str = Field(default=None, foreign_key="user.id")
    # maybe 14 30 days
    expires_at: datetime

    user: Optional[User] = Relationship(back_populates="license")
