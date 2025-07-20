from aiogram import Router, types
from aiogram.filters import CommandStart

from app.bot.kb import keyboard
from app.bot.middleware.admin import AdminMiddleware

start_router = Router()
start_router.message.middleware(AdminMiddleware())


@start_router.message(CommandStart())
async def cmd_start(message: types.Message):
    await message.answer(
        f"Hello, It's License API\n\nWelcome back, {message.from_user.username}",
        reply_markup=keyboard,
    )
