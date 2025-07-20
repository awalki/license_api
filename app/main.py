import logging
from contextlib import asynccontextmanager

import redis.asyncio as redis
from aiogram.types import Update
from aiogram_dialog import setup_dialogs
from fastapi import FastAPI, Request
from fastapi_limiter import FastAPILimiter
from sqlmodel import SQLModel

from app.api.auth_router import auth_router
from app.api.user_router import user_router
from app.api.websocket_router import websocket_router
from app.bot.bot import bot, dp
from app.bot.handlers.admin import admin_router
from app.bot.handlers.start import start_router
from app.bot.state import license_dialog, user_dialog
from app.config import settings
from app.db.database import engine

@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        SQLModel.metadata.create_all(engine)
        redis_connection = redis.from_url(settings.redis_url, encoding="utf8")
        await FastAPILimiter.init(redis_connection)

        dp.include_routers(start_router, admin_router, user_dialog, license_dialog)
        setup_dialogs(dp)
        await bot.set_webhook(settings.webhook_url)
    except Exception as e:
        logging.error(f"[ERROR] Cannot create a table: {e}")
    yield
    logging.info("Shutting down bot...")
    await FastAPILimiter.close()
    await bot.delete_webhook()
    engine.dispose()


app = FastAPI(lifespan=lifespan)

app.include_router(user_router)
app.include_router(auth_router)
app.include_router(websocket_router)


@app.post("/webhook")
async def webhook(request: Request) -> None:
    logging.info("Received webhook request")
    update = Update.model_validate(await request.json(), context={"bot": bot})
    await dp.feed_update(bot, update)
    logging.info("Update processed")
