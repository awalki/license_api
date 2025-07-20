from datetime import datetime, timedelta
from typing import Any

from aiogram.fsm.state import State, StatesGroup
from aiogram.types import Message
from aiogram_dialog import Dialog, DialogManager, Window
from aiogram_dialog.widgets.input import TextInput
from aiogram_dialog.widgets.kbd import Next
from aiogram_dialog.widgets.text import Const

from app.db.database import User, get_session
from app.repos.user import UserRepository


class SG(StatesGroup):
    id = State()
    username = State()
    password = State()
    is_admin = State()
    result = State()


async def success_reg(
    message: Message,
    widget: TextInput,
    dialog_manager: DialogManager,
    data: dict,
) -> None:
    session = get_session().__next__()
    user_repo = UserRepository(session)
    user_data = await getter(dialog_manager)

    user_repo.create_user(
        User(
            id=str(user_data["user_id"]),
            username=str(user_data["username"]),
            password=str(user_data["password"]),
            is_admin=str(user_data["is_admin"]).lower() == "y",
        )
    )

    await message.answer("User was successfully created")
    await dialog_manager.done()


async def error(
    message: Message,
    dialog_: Any,
    manager: DialogManager,
    error_: ValueError,
) -> None:
    await message.answer("Id must be a number!")


async def getter(dialog_manager: DialogManager, **kwargs) -> dict:
    return {
        "user_id": dialog_manager.find("user_id").get_value(),
        "username": dialog_manager.find("username").get_value(),
        "password": dialog_manager.find("password").get_value(),
        "is_admin": dialog_manager.find("is_admin").get_value(),
    }


user_dialog = Dialog(
    Window(
        Const("Enter your id:"),
        TextInput(
            id="user_id",
            on_success=Next(),
            type_factory=int,
            on_error=error,
        ),
        state=SG.id,
    ),
    Window(
        Const("Enter your username:"),
        TextInput(
            id="username",
            on_success=Next(),
        ),
        state=SG.username,
    ),
    Window(
        Const("Enter your password:"),
        TextInput(
            id="password",
            on_success=Next(),
        ),
        state=SG.password,
    ),
    Window(
        Const("Are you an admin? (y/n)"),
        TextInput(
            id="is_admin",
            on_success=success_reg,
        ),
        state=SG.is_admin,
    ),
)


class SGL(StatesGroup):
    username = State()
    duration = State()


async def license_getter(dialog_manager: DialogManager, **kwargs) -> dict:
    return {
        "username": dialog_manager.find("username").get_value(),
        "duration": dialog_manager.find("duration").get_value(),
    }


async def success_license(
    message: Message,
    widget: TextInput,
    dialog_manager: DialogManager,
    data: dict,
) -> None:
    session = get_session().__next__()
    user_repo = UserRepository(session)
    user_data = await license_getter(dialog_manager)
    user = user_repo.get_by_username(user_data["username"])

    if not user:
        await message.answer("User not found!")
        return

    duration_days = int(user_data["duration"])
    duration = datetime.now() + timedelta(days=duration_days)
    user_repo.create_license(user, duration)

    await message.answer(
        f"License for {user.username} has been setted for {duration} days."
    )
    await dialog_manager.done()


license_dialog = Dialog(
    Window(
        Const("Enter username who you want to give license to:"),
        TextInput(
            id="username",
            on_success=Next(),
        ),
        state=SGL.username,
    ),
    Window(
        Const("What time should the license be valid for? (in days)"),
        TextInput(
            id="duration",
            on_success=success_license,
        ),
        state=SGL.duration,
    ),
)