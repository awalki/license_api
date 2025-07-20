from fastapi import APIRouter, Depends, WebSocket

from app.api.deps import get_websocket_service
from app.services.websocket_service import WebSocketService

websocket_router = APIRouter()


@websocket_router.websocket("/ws/notify")
async def websocket_notify(
    ws: WebSocket,
    token: str,
    websocket_service: WebSocketService = Depends(get_websocket_service),
):
    return await websocket_service.websocket_notify(ws, token)
