from contextlib import asynccontextmanager
from datetime import timedelta, datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlmodel import SQLModel, select

from app.admin import admin
from app.auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    get_password_hash,
)
from app.config import settings
from app.database import License, SessionDep, User, engine
from app.schemas import Hwid, LicenseCreate, Token, TokenData
from app.admin import templates


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        SQLModel.metadata.create_all(engine)
    except Exception as e:
        print(f"[ERROR] Cannot create a table: {e}")
    yield

    engine.dispose()


app = FastAPI(lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(admin)

# Prefer to call this endpoint from server (SSR Website, Telegram Bot) to prevent HTTP sniffing using programs like HttpDebugger
@app.post("/auth/reg")
def create_user(*, request: Request,session: SessionDep, user: User):
    db_user = User.model_validate(user)
    db_user.password = get_password_hash(db_user.password)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    users = session.exec(select(User)).all()

    return templates.TemplateResponse("panel.html", {"request": request, "users": users})


@app.post("/auth/login")
def login_user(
    *,
    session: SessionDep,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = session.exec(select(User).where(User.username == form_data.username)).first()

    logged = authenticate_user(user, form_data)
    if not logged:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password, perhaps you don't have an activated license or your account is banned",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={
            "sub": logged.id,
            "username": logged.username,
            "hwid": logged.hwid,
            "is_banned": logged.is_banned,
        },
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/")
async def read_users_me(
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    return current_user


@app.patch("/users/hwid")
async def link_hwid(
    *,
    session: SessionDep,
    current_user: Annotated[TokenData, Depends(get_current_user)],
    hwid: Hwid,
):
    user = session.get(User, current_user.id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.hwid == "not_linked":
        user.hwid = hwid.value

        session.add(user)
        session.commit()
        session.refresh(user)

        return {"message": "hwid has been successfully linked"}

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT, detail="hwid's already linked"
    )

# TODO: implement jwt for admins
# Prefer to call this endpoint from server (SSR Website, Telegram Bot) to prevent HTTP sniffing using programs like HttpDebugger
@app.post("/users/license")
async def create_license(
    *,
    session: SessionDep,
    request: Request,
    license_data: LicenseCreate,
):
    user = session.get(User, license_data.id)

    expires_at = datetime.now(timezone.utc) + timedelta(days=license_data.days)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Create or refresh license
    if user.license:
        session.delete(user.license)
        session.commit()
        session.refresh(user)

    license = License(user_id=user.id, expires_at=expires_at)

    session.add(license)
    session.commit()
    session.refresh(license)

    users = session.query(User).all()

    return templates.TemplateResponse("panel.html", {"request": request, "users": users})
