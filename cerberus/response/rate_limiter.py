from __future__ import annotations

import time
from collections import deque


class RateLimiter:
    """Límite heurístico: N acciones/min global + M isolate_host/hora. Eviction por ventana."""

    def __init__(self, max_actions_per_minute: int, max_isolate_per_hour: int) -> None:
        self._max_min = max_actions_per_minute
        self._max_isolate = max_isolate_per_hour
        self._global: deque[float] = deque()
        self._isolate: deque[float] = deque()

    @staticmethod
    def _evict(dq: deque[float], now: float, window: float) -> None:
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def allow(self, action_type: str) -> bool:
        now = time.monotonic()
        self._evict(self._global, now, 60.0)
        if len(self._global) >= self._max_min:
            return False
        if action_type == "isolate_host":
            self._evict(self._isolate, now, 3600.0)
            if len(self._isolate) >= self._max_isolate:
                return False
            self._isolate.append(now)
        self._global.append(now)
        return True
