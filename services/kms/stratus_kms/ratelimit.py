"""In-memory rate limiting (single-instance deployment).

* TokenBucket       – caps cryptographic calls per user (protects the KMS from floods).
* FailureTracker    – after N access-denied / bad-login events in a window the principal is
                      locked out for a cooling-off period (stops brute-force guessing).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = capacity
        self.refill = refill_per_sec
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(key, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill)
            if tokens < 1:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - 1, now)
            return True


class FailureTracker:
    def __init__(self, max_failures: int, window_sec: float, lockout_sec: float) -> None:
        self.max_failures = max_failures
        self.window = window_sec
        self.lockout = lockout_sec
        self._fails: dict[str, deque[float]] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def locked_for(self, key: str) -> float:
        with self._lock:
            remaining = self._locked_until.get(key, 0) - time.monotonic()
            return max(0.0, remaining)

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            q = self._fails[key]
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.max_failures:
                self._locked_until[key] = now + self.lockout
                q.clear()

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)
            self._locked_until.pop(key, None)


crypto_calls = TokenBucket(capacity=200, refill_per_sec=100)
denied_calls = FailureTracker(max_failures=8, window_sec=60, lockout_sec=30)
login_failures = FailureTracker(max_failures=5, window_sec=60, lockout_sec=60)
