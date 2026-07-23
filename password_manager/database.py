import logging
import sqlite3

from flask import g

logger = logging.getLogger(__name__)


def get_db_path() -> str:
    """Return the configured DB path (set by create_app)."""
    from password_manager.config import Config
    return Config.DB_PATH


def _open_connection() -> sqlite3.Connection:
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def get_db() -> sqlite3.Connection:
    """
    Return a database connection.

    When inside a Flask request, stores the connection on `g` so it is
    reused across the request and automatically closed at teardown.
    Outside requests (e.g. tests, CLI), returns a fresh connection.
    """
    try:
        from flask import has_request_context
        if has_request_context():
            if "db" not in g:
                g.db = _open_connection()
            return g.db
    except RuntimeError:
        pass
    return _open_connection()


def close_db(_exception=None) -> None:
    """Close the database connection at the end of the request."""
    try:
        db = g.pop("db", None)
        if db is not None:
            db.close()
    except RuntimeError:
        pass


def init_db() -> None:
    """Initialize database schema if not already present."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            nonce TEXT NOT NULL,
            url TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vault_service ON vault(service_name);")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vault_username ON vault(username);")

    # Schema migrations: add columns if missing
    try:
        conn.execute("ALTER TABLE vault ADD COLUMN url TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE vault ADD COLUMN notes TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()
    logger.info("Database initialised at %s", get_db_path())


# ---- Settings ----

def get_setting(conn: sqlite3.Connection, key: str) -> "str | None":
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?", (key,)
    ).fetchone()
    return row["value"] if row else None


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


# ---- Vault CRUD ----

def add_entry(
    conn: sqlite3.Connection,
    service_name: str,
    username: str,
    encrypted_password: str,
    nonce: str,
    url: str = "",
    notes: str = "",
) -> int:
    cursor = conn.execute(
        "INSERT INTO vault (service_name, username, encrypted_password, nonce, url, notes) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (service_name, username, encrypted_password, nonce, url, notes),
    )
    assert cursor.lastrowid is not None
    return cursor.lastrowid


def get_all_entries(conn: sqlite3.Connection) -> "list[sqlite3.Row]":
    return conn.execute(
        "SELECT * FROM vault ORDER BY updated_at DESC"
    ).fetchall()


def get_entry(conn: sqlite3.Connection, entry_id: int) -> "sqlite3.Row | None":
    return conn.execute(
        "SELECT * FROM vault WHERE id = ?", (entry_id,)
    ).fetchone()


def update_entry(
    conn: sqlite3.Connection,
    entry_id: int,
    service_name: str,
    username: str,
    encrypted_password: str,
    nonce: str,
    url: str = "",
    notes: str = "",
) -> None:
    conn.execute(
        "UPDATE vault SET service_name=?, username=?, encrypted_password=?, "
        "nonce=?, url=?, notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (service_name, username, encrypted_password, nonce, url, notes, entry_id),
    )


def delete_entry(conn: sqlite3.Connection, entry_id: int) -> None:
    conn.execute("DELETE FROM vault WHERE id = ?", (entry_id,))


def search_entries(conn: sqlite3.Connection, query: str) -> "list[sqlite3.Row]":
    param = f"%{query}%"
    return conn.execute(
        "SELECT * FROM vault WHERE service_name LIKE ? OR username LIKE ? "
        "ORDER BY updated_at DESC",
        (param, param),
    ).fetchall()


def get_all_entries_for_rekey(conn: sqlite3.Connection) -> "list[sqlite3.Row]":
    """Return all entries with encrypted data (for re-encryption during password change)."""
    return conn.execute(
        "SELECT id, encrypted_password, nonce FROM vault"
    ).fetchall()


def update_entry_rekey(
    conn: sqlite3.Connection,
    entry_id: int,
    encrypted_password: str,
    nonce: str,
) -> None:
    """Update only the encrypted fields (used during master password change)."""
    conn.execute(
        "UPDATE vault SET encrypted_password=?, nonce=?, "
        "updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (encrypted_password, nonce, entry_id),
    )
