"""Authentication blueprint: setup, unlock, lock routes."""

import secrets
import logging
from flask import Blueprint, request, session, jsonify, redirect, url_for, render_template

from password_manager.crypto import (
    derive_key,
    encrypt_password,
    decrypt_password,
    generate_salt,
    VERIFICATION_STRING,
)
from password_manager.database import get_db, get_setting, set_setting
from password_manager.utils.security import rate_limit, reset_rate_limit
from password_manager.config import Config

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)

# Per-process in-memory key store: session key_id -> 32-byte encryption key.
# Never persisted or sent to the client.
session_keys: dict[str, bytes] = {}


def get_encryption_key() -> "bytes | None":
    """Return the AES-256 key for the current session, or None if locked."""
    key_id = session.get("key_id")
    if key_id and key_id in session_keys:
        return session_keys[key_id]
    return None


def set_encryption_key(key: bytes) -> None:
    """Store the derived key in memory and bind it to the session."""
    key_id = secrets.token_hex(16)
    session_keys[key_id] = key
    session["key_id"] = key_id
    session["last_active"] = __import__("time").time()


def clear_encryption_key() -> None:
    """Purge the key from memory and invalidate the session."""
    key_id = session.pop("key_id", None)
    if key_id and key_id in session_keys:
        del session_keys[key_id]
    session.clear()


def is_setup_complete() -> bool:
    """Check whether the vault has been initialised (salt exists)."""
    conn = get_db()
    salt = get_setting(conn, "salt")
    return salt is not None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@auth_bp.route("/")
def index():
    return render_template("index.html", setup_needed=not is_setup_complete())


@auth_bp.route("/setup", methods=["POST"])
def setup():
    """
    First-run vault initialisation. Derives the master key, encrypts a
    verification token, persists salt + verification data, and unlocks
    the session immediately.
    """
    if is_setup_complete():
        return jsonify({"error": "Vault already initialised"}), 400

    data = request.get_json(silent=True) or {}
    master_password = data.get("master_password", "")

    if len(master_password) < 8:
        return jsonify({"error": "Master password must be at least 8 characters"}), 400

    salt = generate_salt()
    key = derive_key(master_password, salt, Config.PBKDF2_ITERATIONS)
    verif_ct, verif_nonce = encrypt_password(key, VERIFICATION_STRING)

    conn = get_db()
    with conn:
        set_setting(conn, "salt", salt.hex())
        set_setting(conn, "verification_token", verif_ct)
        set_setting(conn, "verification_nonce", verif_nonce)

    set_encryption_key(key)
    logger.info("Vault initialised successfully")
    return jsonify({"success": True, "redirect": "/vault"})


@auth_bp.route("/unlock", methods=["POST"])
def unlock():
    """
    Authenticate with the master password. Re-derives the key from the
    stored salt and verifies against the encrypted verification token.
    Rate-limited to prevent brute-force attacks.
    """
    client_ip = request.remote_addr or "unknown"

    if not rate_limit(client_ip, max_attempts=5, window_seconds=60):
        logger.warning("Rate limit hit for IP %s", client_ip)
        return jsonify({"error": "Too many attempts. Wait 60 seconds."}), 429

    data = request.get_json(silent=True) or {}
    master_password = data.get("master_password", "")

    if not master_password:
        return jsonify({"error": "Master password is required"}), 400

    conn = get_db()
    salt_hex = get_setting(conn, "salt")
    verif_ct = get_setting(conn, "verification_token")
    verif_nonce = get_setting(conn, "verification_nonce")

    if not all([salt_hex, verif_ct, verif_nonce]):
        return jsonify({"error": "Vault not initialised"}), 400

    salt = bytes.fromhex(salt_hex)
    key = derive_key(master_password, salt, Config.PBKDF2_ITERATIONS)

    try:
        decrypted = decrypt_password(key, verif_ct, verif_nonce)
        if decrypted != VERIFICATION_STRING:
            return jsonify({"error": "Incorrect master password"}), 401
    except Exception:
        return jsonify({"error": "Incorrect master password"}), 401

    reset_rate_limit(client_ip)
    set_encryption_key(key)
    logger.info("Vault unlocked successfully")
    return jsonify({"success": True, "redirect": "/vault"})


@auth_bp.route("/lock")
def lock():
    """Purge the encryption key from memory and return to login."""
    clear_encryption_key()
    logger.info("Vault locked")
    return redirect(url_for("auth.index"))


@auth_bp.route("/change-password", methods=["POST"])
def change_password():
    """
    Change the master password. Re-encrypts all vault entries with the
    new key and updates the verification token.
    """
    key = get_encryption_key()
    if key is None:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")

    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    # Verify old password
    conn = get_db()
    salt_hex = get_setting(conn, "salt")
    salt = bytes.fromhex(salt_hex)
    try:
        test_key = derive_key(old_password, salt, Config.PBKDF2_ITERATIONS)
        verif_ct = get_setting(conn, "verification_token")
        verif_nonce = get_setting(conn, "verification_nonce")
        if decrypt_password(test_key, verif_ct, verif_nonce) != VERIFICATION_STRING:
            return jsonify({"error": "Current password is incorrect"}), 403
    except Exception:
        return jsonify({"error": "Current password is incorrect"}), 403

    # Generate new salt + key
    new_salt = generate_salt()
    new_key = derive_key(new_password, new_salt, Config.PBKDF2_ITERATIONS)

    # Re-encrypt all entries
    from password_manager.database import get_all_entries_for_rekey, update_entry_rekey
    rows = get_all_entries_for_rekey(conn)
    for row in rows:
        plaintext = decrypt_password(key, row["encrypted_password"], row["nonce"])
        new_ct, new_nonce = encrypt_password(new_key, plaintext)
        update_entry_rekey(conn, row["id"], new_ct, new_nonce)

    # Update verification token
    new_verif_ct, new_verif_nonce = encrypt_password(new_key, VERIFICATION_STRING)
    with conn:
        set_setting(conn, "salt", new_salt.hex())
        set_setting(conn, "verification_token", new_verif_ct)
        set_setting(conn, "verification_nonce", new_verif_nonce)

    # Replace active key
    set_encryption_key(new_key)
    clear_encryption_key()
    set_encryption_key(new_key)

    logger.info("Master password changed successfully")
    return jsonify({"success": True})
