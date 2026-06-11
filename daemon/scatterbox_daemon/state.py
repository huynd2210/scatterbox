"""Shared daemon state: one Register, one (optional) unlocked Vault, the
job-wake event and the WebSocket fan-out.

Everything here is touched only from the event loop thread — route handlers
are async and the worker is a loop task, so the sqlite connection never
crosses threads and no locking is needed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import WebSocket

from scatterbox.register import Register
from scatterbox.vault import Vault


class WSManager:
    """Fan-out of daemon events to every connected explorer tab."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    async def broadcast(self, message: dict) -> None:
        for ws in list(self._clients):
            try:
                await ws.send_json(message)
            except Exception:
                # a tab that went away mid-send; drop it quietly
                self._clients.discard(ws)


@dataclass
class DaemonState:
    home: Path
    register: Register
    vault: Vault | None = None  # None = locked; set by POST /api/unlock
    ws: WSManager = field(default_factory=WSManager)
    # The worker sleeps on this; enqueuing a job sets it so work starts
    # immediately instead of on the next poll tick.
    wake: asyncio.Event = field(default_factory=asyncio.Event)
    worker: asyncio.Task | None = None
    # Set by anything that mutates the register; the snapshot loop debounces
    # it into an encrypted register snapshot on the providers (PLAN.md §9).
    dirty: asyncio.Event = field(default_factory=asyncio.Event)
    snapshotter: asyncio.Task | None = None

    @property
    def tmp_dir(self) -> Path:
        path = self.home / "tmp"
        path.mkdir(parents=True, exist_ok=True)
        return path
