"""Scanner plugin modules. Each module exposes an async `run(ctx, client)`."""
from __future__ import annotations

from typing import Awaitable, Callable, Protocol

from ..core import ScanContext

import httpx


class Module(Protocol):
    name: str
    requires_intrusive: bool
    requires_stress: bool

    async def run(self, ctx: ScanContext, client: httpx.AsyncClient) -> None: ...
