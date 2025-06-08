from sqlalchemy.engine.create import create_engine
from sqlmodel import SQLModel, Session, Field

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
engine = create_engine(sqlite_url, echo=True)

def get_session():
    with Session(engine) as session:
        yield session


class User(SQLModel, table=True):
    telegram_id: int = Field(primary_key=True)
    username: str
    password: str
    hwid: str | None = None
    is_banned: bool = Field(default=False)
