"""Simple WebSocket broadcaster running in its own asyncio loop/thread.

Clients connect to receive JSON messages pushed by the sniffer.
"""
import asyncio
import json
import threading
from typing import Set

import websockets

_LOOP: asyncio.AbstractEventLoop | None = None
_CONNECTED: Set[websockets.WebSocketServerProtocol] = set()


async def _handler(ws: websockets.WebSocketServerProtocol, path: str):
    _CONNECTED.add(ws)
    try:
        # Keep the connection open. Clients won't send data.
        await ws.wait_closed()
    finally:
        _CONNECTED.discard(ws)


async def _broadcast(message: str):
    if not _CONNECTED:
        return
    await asyncio.gather(*[ws.send(message) for ws in list(_CONNECTED)])


def broadcast(obj) -> None:
    """Schedule a broadcast of `obj` (will be JSON serialized).

    This function is thread-safe and can be called from the main sniffer
    thread.
    """
    global _LOOP
    if _LOOP is None:
        # No server running; drop silently.
        return
    try:
        message = json.dumps(obj, default=str)
        asyncio.run_coroutine_threadsafe(_broadcast(message), _LOOP)
    except Exception:
        # Never raise from the sniffer path; simply ignore broadcast errors.
        return


def start(host: str = "0.0.0.0", port: int = 8765):
    """Start the websocket server in a background thread.

    Returns the threading.Thread instance running the server loop.
    """
    global _LOOP

    def _run():
        nonlocal host, port
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        server = websockets.serve(_handler, host, port)
        loop.run_until_complete(server)
        globals()['_LOOP'] = loop
        loop.run_forever()

    thr = threading.Thread(target=_run, daemon=True)
    thr.start()
    return thr
