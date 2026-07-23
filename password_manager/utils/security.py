"""Security utilities: rate limiter and security headers."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import flask

# ---- In-memory rate limiter (no external deps) ----

_lock = threading.Lock()
_attempts: dict[str, list[float]] = defaultdict(list)


def rate_limit(key: str, max_attempts: int = 5, window_seconds: int = 60) -> bool:
    """
    Return True if the request is allowed, False if rate-limited.

    Tracks attempts per `key` (e.g. IP address) in a sliding window.
    """
    now = time.time()
    with _lock:
        _attempts[key] = [t for t in _attempts[key] if now - t < window_seconds]
        if len(_attempts[key]) >= max_attempts:
            return False
        _attempts[key].append(now)
        return True


def reset_rate_limit(key: str) -> None:
    """Clear rate-limit state for a key (e.g. after successful login)."""
    with _lock:
        _attempts.pop(key, None)


# ---- Security headers middleware ----

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def add_security_headers(response: flask.Response) -> flask.Response:
    """Attach hardened security headers to every response."""
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';",
    )
    # Strip version info from Server header
    response.headers.pop("Server", None)
    return response
