from typing_extensions import Annotated
from fastapi import Request, HTTPException
from fastapi import Depends
from fastapi.routing import APIRouter
from fastapi.templating import Jinja2Templates
from app.auth import get_current_user
from app.database import User
from sqlmodel import select

from app.database import SessionDep
from app.auth import login_user
from app.schemas import Token

admin = APIRouter(prefix="/admin", tags=["Admin"])

templates = Jinja2Templates(directory="templates")


@admin.patch("/users/{id}")
async def ban_user(
    *,
    request: Request,
    session: SessionDep,
    id: int,
    current_user: Annotated[User, Depends(get_current_user)],
):
    user = session.get(User, id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    user.is_banned = not user.is_banned
    session.commit()
    session.refresh(user)

    users = session.exec(select(User)).all()

    return templates.TemplateResponse(
        request=request,
        name="panel.html",
        context={
            "users": users,
            "token": request.headers.get("Authorization"),
        },
    )


@admin.post("/login")
async def login(
    *,
    session: SessionDep,
    request: Request,
    token: Annotated[Token, Depends(login_user)],
):
    users = session.exec(select(User)).all()

    current_user = await get_current_user(token.access_token)

    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")

    return templates.TemplateResponse(
        request=request,
        name="panel.html",
        context={"users": users, "token": f"Bearer {token.access_token}"},
    )


@admin.get("/")
async def index(*, session: SessionDep, request: Request):
    users = session.exec(select(User)).all()

    if not users:
        return templates.TemplateResponse(
            request=request,
            name="create_adm.html",
        )

    return templates.TemplateResponse(request=request, name="index.html")
