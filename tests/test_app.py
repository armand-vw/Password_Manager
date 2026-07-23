import pytest
from password_manager import create_app


@pytest.fixture
def app():
    """Create a test app with a temporary in-memory DB."""
    import os
    os.environ["PM_DB_DIR"] = "/tmp"
    os.environ["PM_DB_NAME"] = "test_vault.db"
    os.environ["PM_SECRET_KEY"] = "test-secret-key-32-bytes!!"
    os.environ["PM_AUTO_LOCK_MINUTES"] = "0"

    app = create_app()
    app.config.update(TESTING=True)

    # Wipe test DB
    from password_manager.database import get_db_path
    db_path = get_db_path()
    if os.path.exists(db_path):
        os.remove(db_path)
    from password_manager.database import init_db
    init_db()

    yield app

    # Cleanup
    import os
    db_path = get_db_path()
    if os.path.exists(db_path):
        os.remove(db_path)
    if os.path.exists(os.path.join("/tmp", ".secret_key")):
        os.remove(os.path.join("/tmp", ".secret_key"))


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def unlocked_client(client):
    """Setup and unlock a vault for testing."""
    client.post("/setup", json={"master_password": "TestMaster123!"})
    return client


class TestCrypto:
    def test_derive_key(self):
        from password_manager.crypto import derive_key, generate_salt
        salt = generate_salt()
        key1 = derive_key("password", salt)
        key2 = derive_key("password", salt)
        key3 = derive_key("different", salt)
        assert len(key1) == 32
        assert key1 == key2
        assert key1 != key3

    def test_encrypt_decrypt_roundtrip(self):
        from password_manager.crypto import derive_key, encrypt_password, decrypt_password, generate_salt
        salt = generate_salt()
        key = derive_key("masterpass", salt)
        ct, nonce = encrypt_password(key, "MySecret123!")
        result = decrypt_password(key, ct, nonce)
        assert result == "MySecret123!"

    def test_decrypt_wrong_key_fails(self):
        from password_manager.crypto import derive_key, encrypt_password, decrypt_password, generate_salt
        from cryptography.exceptions import InvalidTag
        salt = generate_salt()
        key1 = derive_key("correct", salt)
        key2 = derive_key("wrong", salt)
        ct, nonce = encrypt_password(key1, "secret")
        with pytest.raises(Exception):
            decrypt_password(key2, ct, nonce)

    def test_password_strength_weak(self):
        from password_manager.crypto import password_strength
        result = password_strength("abc")
        assert result["score"] <= 2

    def test_password_strength_strong(self):
        from password_manager.crypto import password_strength
        result = password_strength("T5$k9mP!xL2@wQ8nR")
        assert result["score"] >= 3

    def test_generate_password(self):
        from password_manager.crypto import generate_password
        pwd = generate_password(32)
        assert len(pwd) == 32
        pwd2 = generate_password(24, uppercase=False, digits=False, symbols=False)
        assert all(c.islower() for c in pwd2)


class TestDatabase:
    def test_init_db(self, app):
        from password_manager.database import get_db, get_all_entries
        conn = get_db()
        entries = get_all_entries(conn)
        assert entries == []

    def test_add_and_get_entries(self, app):
        from password_manager.database import get_db, add_entry, get_all_entries
        conn = get_db()
        add_entry(conn, "GitHub", "user", "encpass", "nonce123")
        conn.commit()
        entries = get_all_entries(conn)
        assert len(entries) == 1
        assert entries[0]["service_name"] == "GitHub"

    def test_search_entries(self, app):
        from password_manager.database import get_db, add_entry, search_entries
        conn = get_db()
        add_entry(conn, "GitHub", "alice", "enc1", "n1")
        add_entry(conn, "BitBucket", "bob", "enc2", "n2")
        conn.commit()
        results = search_entries(conn, "git")
        assert len(results) == 1
        assert results[0]["service_name"] == "GitHub"
        results = search_entries(conn, "alice")
        assert len(results) == 1
        results = search_entries(conn, "xyz")
        assert len(results) == 0

    def test_update_entry(self, app):
        from password_manager.database import get_db, add_entry, update_entry, get_entry
        conn = get_db()
        eid = add_entry(conn, "Old", "old", "enc", "n")
        conn.commit()
        update_entry(conn, eid, "New", "new", "enc2", "n2")
        conn.commit()
        entry = get_entry(conn, eid)
        assert entry["service_name"] == "New"
        assert entry["username"] == "new"

    def test_delete_entry(self, app):
        from password_manager.database import get_db, add_entry, delete_entry, get_entry
        conn = get_db()
        eid = add_entry(conn, "X", "y", "e", "n")
        conn.commit()
        delete_entry(conn, eid)
        conn.commit()
        assert get_entry(conn, eid) is None


class TestAuthRoutes:
    def test_index_shows_setup(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Create Master Password" in resp.data

    def test_setup_creates_vault(self, client):
        resp = client.post("/setup", json={"master_password": "SecurePass123!"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["redirect"] == "/vault"

    def test_setup_too_short(self, client):
        resp = client.post("/setup", json={"master_password": "short"})
        assert resp.status_code == 400

    def test_setup_already_initialised(self, unlocked_client):
        resp = unlocked_client.post("/setup", json={"master_password": "AnotherPass1!"})
        assert resp.status_code == 400

    def test_unlock_correct(self, client):
        client.post("/setup", json={"master_password": "CorrectHorse1!"})
        client.get("/lock")
        resp = client.post("/unlock", json={"master_password": "CorrectHorse1!"})
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_unlock_wrong(self, client):
        client.post("/setup", json={"master_password": "CorrectHorse1!"})
        client.get("/lock")
        resp = client.post("/unlock", json={"master_password": "WrongPassword!"})
        assert resp.status_code == 401

    def test_lock_clears_session(self, unlocked_client):
        resp = unlocked_client.get("/lock")
        assert resp.status_code == 302
        # After lock, vault is inaccessible
        resp = unlocked_client.get("/vault")
        assert resp.status_code == 302


class TestVaultRoutes:
    def test_vault_requires_auth(self, client):
        resp = client.get("/vault")
        assert resp.status_code == 302

    def test_vault_accessible_when_unlocked(self, unlocked_client):
        resp = unlocked_client.get("/vault")
        assert resp.status_code == 200

    def test_add_entry(self, unlocked_client):
        resp = unlocked_client.post("/api/entries", json={
            "service_name": "GitHub", "username": "dev", "password": "gh_pass"
        })
        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_get_entries(self, unlocked_client):
        unlocked_client.post("/api/entries", json={
            "service_name": "GitHub", "username": "dev", "password": "gh_pass"
        })
        resp = unlocked_client.get("/api/entries")
        data = resp.get_json()
        assert len(data["entries"]) == 1
        assert data["entries"][0]["password"] == "gh_pass"

    def test_search_entries(self, unlocked_client):
        unlocked_client.post("/api/entries", json={
            "service_name": "GitHub", "username": "alice", "password": "p1"
        })
        unlocked_client.post("/api/entries", json={
            "service_name": "GitLab", "username": "bob", "password": "p2"
        })
        resp = unlocked_client.get("/api/entries?q=hub")
        data = resp.get_json()
        assert len(data["entries"]) == 1
        assert data["entries"][0]["service_name"] == "GitHub"

    def test_update_entry(self, unlocked_client):
        r = unlocked_client.post("/api/entries", json={
            "service_name": "Old", "username": "u", "password": "p"
        })
        eid = r.get_json()["id"]
        resp = unlocked_client.put(f"/api/entries/{eid}", json={
            "service_name": "New", "username": "u", "password": "p2"
        })
        assert resp.get_json()["success"] is True
        entries = unlocked_client.get("/api/entries").get_json()["entries"]
        assert entries[0]["service_name"] == "New"

    def test_delete_entry(self, unlocked_client):
        r = unlocked_client.post("/api/entries", json={
            "service_name": "X", "username": "y", "password": "z"
        })
        eid = r.get_json()["id"]
        resp = unlocked_client.delete(f"/api/entries/{eid}")
        assert resp.get_json()["success"] is True
        entries = unlocked_client.get("/api/entries").get_json()["entries"]
        assert len(entries) == 0

    def test_generate_password(self, unlocked_client):
        resp = unlocked_client.get("/api/generate?len=32")
        data = resp.get_json()
        assert len(data["password"]) == 32
        assert "strength" in data

    def test_password_strength_check(self, unlocked_client):
        resp = unlocked_client.post("/api/strength", json={"password": "abc"})
        data = resp.get_json()
        assert data["score"] <= 2
        resp = unlocked_client.post("/api/strength", json={"password": "A9$kL2@pX!qZ5"})
        data = resp.get_json()
        assert data["score"] >= 3

    def test_export(self, unlocked_client):
        unlocked_client.post("/api/entries", json={
            "service_name": "G", "username": "u", "password": "p"
        })
        resp = unlocked_client.get("/api/export")
        data = resp.get_json()
        assert data["count"] == 1
        assert '"service_name"' in data["data"]

    def test_import_entries(self, unlocked_client):
        json_data = '[{"service_name":"Imported","username":"i","password":"ipass"}]'
        resp = unlocked_client.post("/api/import", json={"data": json_data})
        assert resp.get_json()["imported"] == 1
        entries = unlocked_client.get("/api/entries").get_json()["entries"]
        assert entries[0]["service_name"] == "Imported"

    def test_health(self, unlocked_client):
        resp = unlocked_client.get("/api/health")
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["db"] == "connected"

    def test_change_password(self, unlocked_client):
        unlocked_client.post("/api/entries", json={
            "service_name": "G", "username": "u", "password": "orig_pass"
        })
        resp = unlocked_client.post("/change-password", json={
            "old_password": "TestMaster123!", "new_password": "NewMaster456!"
        })
        assert resp.get_json()["success"] is True
        # Old entries should still decrypt with new key
        entries = unlocked_client.get("/api/entries").get_json()["entries"]
        assert entries[0]["password"] == "orig_pass"
        # Lock and unlock with new password
        unlocked_client.get("/lock")
        resp = unlocked_client.post("/unlock", json={"master_password": "NewMaster456!"})
        assert resp.get_json()["success"] is True
        entries = unlocked_client.get("/api/entries").get_json()["entries"]
        assert entries[0]["password"] == "orig_pass"

    def test_url_and_notes_fields(self, unlocked_client):
        r = unlocked_client.post("/api/entries", json={
            "service_name": "GitHub", "username": "dev", "password": "p",
            "url": "https://github.com", "notes": "Personal account"
        })
        eid = r.get_json()["id"]
        resp = unlocked_client.get(f"/api/entries/{eid}")
        entry = resp.get_json()["entry"]
        assert entry["url"] == "https://github.com"
        assert entry["notes"] == "Personal account"
