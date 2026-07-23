"""Vault blueprint: dashboard, CRUD API, password generator, export/import."""

import json
import logging

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

from password_manager.auth.routes import get_encryption_key
from password_manager.crypto import (
    decrypt_password,
    encrypt_password,
    generate_password,
    password_strength,
)
from password_manager.database import (
    get_db,
    add_entry,
    get_all_entries,
    get_entry,
    update_entry,
    delete_entry,
    search_entries,
)

logger = logging.getLogger(__name__)

vault_bp = Blueprint("vault", __name__)


# ---- Page route ----


@vault_bp.route("/vault")
def vault():
    if get_encryption_key() is None:
        return redirect(url_for("auth.index"))
    return render_template("vault.html")


# ---- Helpers ----


def _require_key():
    key = get_encryption_key()
    if key is None:
        return None
    return key


def _decrypt_row(key: bytes, row) -> "dict | None":
    try:
        plaintext = decrypt_password(key, row["encrypted_password"], row["nonce"])
        return {
            "id": row["id"],
            "service_name": row["service_name"],
            "username": row["username"],
            "password": plaintext,
            "url": row["url"] or "",
            "notes": row["notes"] or "",
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    except Exception:
        logger.warning("Failed to decrypt entry %s", row["id"])
        return None


# ---- Entries API ----


@vault_bp.route("/api/entries", methods=["GET"])
def api_get_entries():
    key = _require_key()
    if key is None:
        return jsonify({"error": "Not authenticated"}), 401

    query = request.args.get("q", "")
    conn = get_db()
    rows = search_entries(conn, query) if query else get_all_entries(conn)

    entries = []
    for row in rows:
        entry = _decrypt_row(key, row)
        if entry:
            entries.append(entry)

    return jsonify({"entries": entries})


@vault_bp.route("/api/entries/<int:entry_id>", methods=["GET"])
def api_get_entry(entry_id):
    key = _require_key()
    if key is None:
        return jsonify({"error": "Not authenticated"}), 401

    conn = get_db()
    row = get_entry(conn, entry_id)
    if row is None:
        return jsonify({"error": "Entry not found"}), 404

    entry = _decrypt_row(key, row)
    if entry is None:
        return jsonify({"error": "Decryption failed"}), 500

    return jsonify({"entry": entry})


@vault_bp.route("/api/entries", methods=["POST"])
def api_add_entry():
    key = _require_key()
    if key is None:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    service_name = data.get("service_name", "").strip()
    username = data.get("username", "").strip()
    plaintext = data.get("password", "").strip()
    url = data.get("url", "").strip()
    notes = data.get("notes", "").strip()

    if not all([service_name, username, plaintext]):
        return jsonify({"error": "Service, username, and password are required"}), 400

    ct, nonce = encrypt_password(key, plaintext)
    conn = get_db()
    with conn:
        entry_id = add_entry(conn, service_name, username, ct, nonce, url, notes)

    logger.info("Entry %d added (%s)", entry_id, service_name)
    return jsonify({"success": True, "id": entry_id})


@vault_bp.route("/api/entries/<int:entry_id>", methods=["PUT"])
def api_update_entry(entry_id):
    key = _require_key()
    if key is None:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    service_name = data.get("service_name", "").strip()
    username = data.get("username", "").strip()
    plaintext = data.get("password", "").strip()
    url = data.get("url", "").strip()
    notes = data.get("notes", "").strip()

    if not all([service_name, username, plaintext]):
        return jsonify({"error": "Service, username, and password are required"}), 400

    ct, nonce = encrypt_password(key, plaintext)
    conn = get_db()
    with conn:
        update_entry(conn, entry_id, service_name, username, ct, nonce, url, notes)

    logger.info("Entry %d updated (%s)", entry_id, service_name)
    return jsonify({"success": True})


@vault_bp.route("/api/entries/<int:entry_id>", methods=["DELETE"])
def api_delete_entry(entry_id):
    key = _require_key()
    if key is None:
        return jsonify({"error": "Not authenticated"}), 401

    conn = get_db()
    with conn:
        delete_entry(conn, entry_id)

    logger.info("Entry %d deleted", entry_id)
    return jsonify({"success": True})


# ---- Password Generator ----


@vault_bp.route("/api/generate")
def api_generate():
    key = _require_key()
    if key is None:
        return jsonify({"error": "Not authenticated"}), 401

    length = request.args.get("len", 24, type=int)
    length = max(8, min(128, length))

    uppercase = request.args.get("upper", "1") == "1"
    digits = request.args.get("digits", "1") == "1"
    symbols = request.args.get("symbols", "1") == "1"
    exclude_ambiguous = request.args.get("noambig", "0") == "1"

    pwd = generate_password(length, uppercase, digits, symbols, exclude_ambiguous)
    strength = password_strength(pwd)
    return jsonify({"password": pwd, "strength": strength})


# ---- Password Strength Check ----


@vault_bp.route("/api/strength", methods=["POST"])
def api_strength():
    key = _require_key()
    if key is None:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    pwd = data.get("password", "")
    return jsonify(password_strength(pwd))


# ---- Export / Import ----


@vault_bp.route("/api/export")
def api_export():
    key = _require_key()
    if key is None:
        return jsonify({"error": "Not authenticated"}), 401

    conn = get_db()
    rows = get_all_entries(conn)
    data = []
    for row in rows:
        entry = _decrypt_row(key, row)
        if entry:
            data.append({
                "service_name": entry["service_name"],
                "username": entry["username"],
                "password": entry["password"],
                "url": entry["url"],
                "notes": entry["notes"],
            })

    export_json = json.dumps(data, indent=2, ensure_ascii=False)
    return jsonify({"data": export_json, "count": len(data)})


@vault_bp.route("/api/import", methods=["POST"])
def api_import():
    key = _require_key()
    if key is None:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    import_data = data.get("data", "")
    overwrite = data.get("overwrite", False)

    try:
        entries = json.loads(import_data)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON"}), 400

    if not isinstance(entries, list):
        return jsonify({"error": "Expected a JSON array of entries"}), 400

    conn = get_db()
    imported = 0
    skipped = 0

    with conn:
        if overwrite:
            conn.execute("DELETE FROM vault")

        for entry in entries:
            svc = entry.get("service_name", "").strip()
            usr = entry.get("username", "").strip()
            pwd = entry.get("password", "").strip()
            if not svc or not pwd:
                skipped += 1
                continue
            url = entry.get("url", "").strip()
            notes = entry.get("notes", "").strip()
            ct, nonce = encrypt_password(key, pwd)
            add_entry(conn, svc, usr, ct, nonce, url, notes)
            imported += 1

    logger.info("Import: %d imported, %d skipped", imported, skipped)
    return jsonify({"success": True, "imported": imported, "skipped": skipped})


# ---- Health ----


@vault_bp.route("/api/health")
def api_health():
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        db_status = "connected"
    except Exception:
        db_status = "error"

    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "db": db_status,
    })
