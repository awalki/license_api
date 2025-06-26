from contextlib import asynccontextmanager
from datetime import timedelta, datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.staticfiles import StaticFiles
from sqlmodel import SQLModel, select

from app.admin import admin
from app.auth import (
    get_current_user,
    get_password_hash,
)
from app.config import settings
from app.database import License, SessionDep, User, engine
from app.schemas import AdminCreate, Hwid, LicenseCreate, TokenData
from app.admin import templates
from app.auth import auth_router


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
app.include_router(auth_router)


def try_create_user(*, session: SessionDep, user: User):
    db_user = User.model_validate(user)
    db_user.password = get_password_hash(db_user.password)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)


@app.post("/auth/reg")
def create_user(
    *,
    request: Request,
    current_user: Annotated[TokenData, Depends(get_current_user)],
    session: SessionDep,
    user: User,
):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not an admin",
        )

    try_create_user(session=session, user=user)

    users = session.exec(select(User)).all()

    return templates.TemplateResponse(
        "panel.html",
        {
            "request": request,
            "token": request.headers.get("Authorization"),
            "users": users,
        },
    )


# Only through admin panel
@app.post("/auth/reg-admin")
def create_admin(*, request: Request, session: SessionDep, admin: AdminCreate):
    if settings.admin_password != admin.apassword:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Incorrect admin password",
        )

    new_admin = User(
        id=admin.id, username=admin.username, password=admin.password, is_admin=True
    )

    try_create_user(session=session, user=new_admin)

    users = session.exec(select(User)).all()

    return templates.TemplateResponse(
        "panel.html",
        {
            "request": request,
            "token": request.headers.get("Authorization"),
            "users": users,
        },
    )


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


# Do not call this endpoint through the client or that could be sniffed
@app.post("/users/license")
async def create_license(
    *,
    session: SessionDep,
    request: Request,
    license_data: LicenseCreate,
    current_user: Annotated[TokenData, Depends(get_current_user)],
):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

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

    return templates.TemplateResponse(
        "panel.html",
        {
            "request": request,
            "token": request.headers.get("Authorization"),
            "users": users,
        },
    )
