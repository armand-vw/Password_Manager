"""Configuration loader with .env support and sensible defaults."""

import os
from pathlib import Path
import secrets


BASE_DIR = Path(__file__).resolve().parent.parent
DB_DIR = os.environ.get("PM_DB_DIR", str(BASE_DIR))


class Config:
    SECRET_KEY: str = os.environ.get(
        "PM_SECRET_KEY",
        secrets.token_hex(32),
    )
    HOST: str = os.environ.get("PM_HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PM_PORT", "8080"))
    DB_PATH: str = os.path.join(DB_DIR, os.environ.get("PM_DB_NAME", "vault.db"))

    # PBKDF2 iterations  (600k is OWASP recommendation)
    PBKDF2_ITERATIONS: int = int(
        os.environ.get("PM_PBKDF2_ITERATIONS", "600000")
    )

    # Auto-lock after N minutes of inactivity (0 = disabled)
    AUTO_LOCK_MINUTES: int = int(os.environ.get("PM_AUTO_LOCK_MINUTES", "5"))

    # Rate limiting: max unlock attempts per minute per IP
    RATE_LIMIT_UNLOCK: str = os.environ.get("PM_RATE_LIMIT_UNLOCK", "5 per minute")

    # Flask session lifetime in hours
    SESSION_LIFETIME_HOURS: int = int(
        os.environ.get("PM_SESSION_LIFETIME_HOURS", "8")
    )

    @classmethod
    def ensure_secret_key_file(cls) -> None:
        """Persist SECRET_KEY to disk so restarts don't invalidate sessions."""
        key_file = os.path.join(DB_DIR, ".secret_key")
        if not os.path.exists(key_file):
            with open(key_file, "w") as f:
                f.write(cls.SECRET_KEY)
            os.chmod(key_file, 0o600)
        else:
            with open(key_file) as f:
                cls.SECRET_KEY = f.read().strip()

    @classmethod
    def from_env(cls) -> "Config":
        cls.ensure_secret_key_file()
        return cls()
