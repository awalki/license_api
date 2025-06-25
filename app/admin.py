from fastapi import Request, Form, HTTPException
from fastapi.routing import APIRouter
from fastapi.templating import Jinja2Templates
from typing import Annotated
from app.database import User
from sqlmodel import select
from app.config import settings

from app.database import SessionDep

admin = APIRouter(prefix="/admin", tags=["Admin"])

templates = Jinja2Templates(directory="templates")

@admin.post("/login")
async def login(*, session: SessionDep, request: Request, username: Annotated[str, Form()], password: Annotated[str, Form()]):
    user = {
        "username": "admin",
        "password": settings.admin_password
    }

    if password != user["password"] or username != user["username"] or user["username"] != username:
        raise HTTPException(status_code=401, detail="Invalid credentials")


    users = session.exec(select(User)).all()

    return templates.TemplateResponse(
        request=request,
        name="panel.html",
        context={"users": users}
    )

@admin.get("/")
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html"
    )
