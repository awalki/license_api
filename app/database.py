from typing import Annotated

from fastapi import Depends
from sqlmodel import Field, Session, SQLModel, create_engine

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
engine = create_engine(sqlite_url, echo=True)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


class User(SQLModel, table=True):
    telegram_id: str = Field(primary_key=True)
    username: str
    password: str
    hwid: str | None = None
    is_banned: bool = Field(default=False)
