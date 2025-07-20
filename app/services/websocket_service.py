import logging
from fastapi import WebSocket, WebSocketDisconnect
import jwt

from app.repos.user import UserRepository
from app.config import settings
from app.services.bot_service import BotService


class WebSocketService(BotService):
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo
        self.connected_clients = set()

    async def websocket_notify(self, ws: WebSocket, token: str):
        await ws.accept()
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])

            username = payload.get("username")
            
            user = self.user_repo.get_by_username(username)
            if not user:
                await ws.close(code=1008)
                return
            
            self.connected_clients.add(ws)

            await self.handle_launch(user)
            while True:
                text = await ws.receive_text()

                if text == "ping":
                    await ws.send_text("pong")

        except Exception:
            await ws.close(code=1008)
            logging.info(f"Client {ws.client.host} disconnected")
