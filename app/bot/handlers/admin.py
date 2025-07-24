from aiogram import F, Router, types
from aiogram_dialog import DialogManager, StartMode

from app.bot.middleware.admin import AdminMiddleware
from app.bot.state import SG, SGL

admin_router = Router()
admin_router.message.middleware(AdminMiddleware())


@admin_router.message(F.text.lower().contains("register"))
async def register_user(message: types.Message, dialog_manager: DialogManager):
    await dialog_manager.start(state=SG.id, mode=StartMode.RESET_STACK)


@admin_router.message(F.text.lower().contains("license"))
async def give_license(message: types.Message, dialog_manager: DialogManager):
    await dialog_manager.start(state=SGL.username, mode=StartMode.RESET_STACK)
