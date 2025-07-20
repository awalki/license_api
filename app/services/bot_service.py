from app.bot.bot import bot
from app.config import settings
from app.db.database import User


class BotService:
    def __init__(self) -> None:
        pass

    async def handle_launch(self, user: User | None) -> None:
        await bot.send_message(
            settings.admin_id, f"{user.username} has launched the software"
        )
