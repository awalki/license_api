from fastapi import WebSocket, WebSocketDisconnect
from app.repos.user import UserRepository
from app.services.bot_service import BotService


class WebSocketService(BotService):
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo
        self.connected_clients = set()

    async def websocket_notify(self, ws: WebSocket, username: str):
        await ws.accept()
        try:
            user = self.user_repo.get_by_username(username)

            self.connected_clients.add(ws)

            await self.handle_launch(user)
            while True:
                text = await ws.receive_text()

                if text == "ping":
                    await ws.send_text("pong")

        except WebSocketDisconnect:
            print("ws disconnected")
