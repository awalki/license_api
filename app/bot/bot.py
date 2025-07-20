from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.base import DefaultKeyBuilder
from aiogram.fsm.storage.redis import RedisStorage

from app.config import settings

key_builder = DefaultKeyBuilder(with_destiny=True)

storage = RedisStorage.from_url(settings.redis_url)
storage.key_builder = key_builder

bot = Bot(token=settings.bot_token)
dp = Dispatcher(storage=storage)
