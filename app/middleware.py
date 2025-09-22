from __future__ import annotations

import time
from typing import Dict, Tuple

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware


class ApiKeyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, api_key: str | None):
        super().__init__(app)
        self.api_key = api_key

    async def dispatch(self, request: Request, call_next):
        if self.api_key:
            key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
            if key != self.api_key:
                raise HTTPException(status_code=401, detail="Invalid API key")
        return await call_next(request)


class TokenBucketLimiter(BaseHTTPMiddleware):
    """Simple in-memory token bucket per client IP.

    Not distributed-safe; for single-process API nodes or small clusters.
    Configure: capacity tokens and refill rate tokens/sec.
    """

    def __init__(self, app, capacity: int = 30, refill_rate: float = 10.0):
        super().__init__(app)
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.state: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_ts)

    def _allow(self, ip: str) -> bool:
        now = time.monotonic()
        tokens, last = self.state.get(ip, (self.capacity, now))
        # Refill
        tokens = min(self.capacity, tokens + (now - last) * self.refill_rate)
        if tokens < 1.0:
            self.state[ip] = (tokens, now)
            return False
        self.state[ip] = (tokens - 1.0, now)
        return True

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "anon"
        if not self._allow(ip):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        return await call_next(request)

