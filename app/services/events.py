"""A tiny fan-out hub so the console reflects agent activity without polling.

Progress updates arrive on worker threads (regular def endpoints), while the
WebSocket writers live on the event loop. ``broadcast`` bridges the two by
scheduling onto the loop captured at startup, and silently no-ops before the
loop exists so imports stay side-effect free during tests.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger("douglas.events")

_loop: asyncio.AbstractEventLoop | None = None
_clients: set[Any] = set()


def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _loop
    _loop = loop


def register(ws: Any) -> None:
    _clients.add(ws)


def unregister(ws: Any) -> None:
    _clients.discard(ws)


def client_count() -> int:
    return len(_clients)


async def _push(message: str) -> None:
    dead = []
    for ws in list(_clients):
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _clients.discard(ws)


def broadcast(payload: dict) -> None:
    """Send an event to every attached console. Never raises."""
    if not _clients or _loop is None:
        return
    try:
        message = json.dumps(payload, default=str)
        asyncio.run_coroutine_threadsafe(_push(message), _loop)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("broadcast failed: %s", exc)
