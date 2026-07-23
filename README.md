# Password Manager

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/armand-vw/Password_Manager/actions/workflows/ci.yml/badge.svg)](https://github.com/armand-vw/Password_Manager/actions)
[![Tests](https://img.shields.io/badge/tests-32%20passed-brightgreen.svg)](tests/)

A **local, zero-knowledge encrypted password manager** web application built with Python, Flask, and production-grade cryptography. Your master password is never stored — only you can unlock your vault.

---

## Why This Project

Most password managers run as cloud services or browser extensions that require trusting a third party with your credentials. This project demonstrates how to build a **cryptographically sound, local-first password manager** from scratch — the way a security engineer would design it.

Every cryptographic decision is intentional: PBKDF2 with 600,000 iterations (OWASP 2023 recommendation), AES-256-GCM for authenticated encryption, unique nonces per operation, and in-memory-only key storage. There are no shortcuts.

---

## Security Model

```
┌──────────────┐     PBKDF2-SHA256      ┌──────────────┐
│  Master      │ ──────────────────────▶ │  32-byte     │
│  Password    │    600,000 iters        │  AES Key     │
└──────────────┘     + 16-byte salt      └──────┬───────┘
                                                │
                              ┌─────────────────┘
                              ▼
┌──────────────┐     AES-256-GCM        ┌──────────────┐
│  Plaintext   │ ──────────────────────▶ │  Encrypted   │
│  Password    │    unique 12-byte       │  Ciphertext  │
│              │    nonce per op         │  + Nonce     │
└──────────────┘                        └──────┬───────┘
                                               │
                                         ┌─────▼──────┐
                                         │   SQLite   │
                                         │   (WAL)    │
                                         └────────────┘
```

### Key guarantees

| Property | Implementation |
|---|---|
| **Zero-knowledge** | Master password is never persisted. Derived key lives only in server memory. |
| **At-rest encryption** | Every stored password is AES-256-GCM encrypted with a unique nonce. |
| **Authenticated encryption** | GCM provides both confidentiality and integrity. Tampered ciphertexts fail to decrypt. |
| **Brute-force resistance** | PBKDF2-SHA256 at 600,000 iterations (~0.5s per attempt). Rate-limited to 5 attempts/min. |
| **Session safety** | Derived key is keyed by a random `key_id` in Flask's signed session. `/lock` purges the key immediately. |
| **Auto-lock** | Configurable inactivity timer (default 5 min). Server-enforced. |
| **No secrets in transit** | Runs entirely on localhost. Security headers (CSP, HSTS, X-Frame-Options) prevent XSS and clickjacking. |
| **Forward secrecy** | Changing the master password re-encrypts every vault entry with a new salt + key. |

---

## Features

- **AES-256-GCM encryption** with unique 12-byte nonce per operation
- **PBKDF2-SHA256 key derivation** at 600,000+ iterations (OWASP recommended)
- **Zero-knowledge architecture** — master password never stored, key never leaves memory
- **Instant full-text search** on service name and username (indexed SQLite)
- **Password generator** with configurable length, character sets, and ambiguous character exclusion
- **Real-time strength meter** with entropy estimation and feedback
- **Auto-lock** after configurable inactivity timeout
- **Master password change** with full vault re-encryption
- **Export / Import** as plaintext JSON for backup and migration
- **Rate limiting** — 5 unlock attempts per minute per IP
- **Security headers** — CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Keyboard shortcuts** — `Ctrl+N` new, `Ctrl+S` search, `Ctrl+L` lock, `Esc` close modals
- **Dark themed responsive UI** — clean single-page dashboard
- **URL + Notes fields** on every entry with quick-launch links

---

## Quick Start

```bash
git clone https://github.com/armand-vw/Password_Manager.git
cd Password_Manager
pip install flask cryptography
python app.py
```

Then visit **http://localhost:8080**. On first visit you'll create a master password (8+ characters). Subsequent visits unlock with the same password.

Or use the launcher:

```bash
./run.sh    # auto-opens browser
```

### Configuration

Copy `.env.example` to `.env` and adjust:

| Variable | Default | Description |
|---|---|---|
| `PM_HOST` | `0.0.0.0` | Bind address |
| `PM_PORT` | `8080` | Listen port |
| `PM_DB_DIR` | `.` | Database directory |
| `PM_DB_NAME` | `vault.db` | Database filename |
| `PM_AUTO_LOCK_MINUTES` | `5` | Auto-lock timeout (0 = disabled) |
| `PM_RATE_LIMIT_UNLOCK` | `5 per minute` | Brute-force protection |
| `PM_SESSION_LIFETIME_HOURS` | `8` | Max session duration |
| `PM_PBKDF2_ITERATIONS` | `600000` | Key derivation iterations |

---

## Architecture

```
Password_Manager/
├── app.py                          # Entry point
├── pyproject.toml                  # Build config, linting, testing tools
├── password_manager/
│   ├── __init__.py                 # create_app() factory
│   ├── config.py                   # .env loader, persistent SECRET_KEY
│   ├── crypto.py                   # PBKDF2 + AES-256-GCM + strength + generator
│   ├── database.py                 # SQLite WAL, CRUD, search, auto-migrations
│   ├── auth/
│   │   └── routes.py               # Setup, unlock, lock, change password
│   ├── vault/
│   │   └── routes.py               # Dashboard, CRUD API, export/import, health
│   └── utils/
│       └── security.py             # Rate limiter, security headers (CSP)
├── tests/
│   └── test_app.py                 # 32 tests across 4 test classes
├── templates/
│   ├── index.html                  # Login/setup with live strength meter
│   └── vault.html                  # Full SPA dashboard
├── static/style.css                # Dark theme CSS
├── .github/workflows/ci.yml        # CI: lint → type-check → test
├── README.md
└── LICENSE
```

### Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.x |
| Cryptography | `cryptography` (hazmat layer — PBKDF2, AES-GCM) |
| Database | SQLite 3 (WAL mode, atomic transactions) |
| Frontend | Vanilla JavaScript, CSS custom properties |
| Testing | pytest (32 tests), Flask test client |
| Linting | ruff, mypy (strict) |
| CI/CD | GitHub Actions (3 Python versions) |

---

## Cryptography Details

| Component | Algorithm | Configuration |
|---|---|---|
| Key derivation | PBKDF2HMAC | SHA-256, 600,000 iterations, 32-byte key |
| Encryption | AES-256-GCM | 12-byte unique nonce per encryption |
| Authentication tag | GCM (built-in) | 128-bit, verified on every decryption |
| Salt | `os.urandom(16)` | Stored in `settings` table as hex |
| Master verification | Encrypted token | `"MASTER_VERIFIED_OK"` encrypted with derived key |
| Nonce | `os.urandom(12)` | Unique per encryption — prevents nonce-reuse |

---

## API Reference

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/` | GET | No | Login/setup page |
| `/setup` | POST | No | First-run vault initialisation |
| `/unlock` | POST | No | Authenticate with master password |
| `/lock` | GET | Yes | Purge key, clear session |
| `/change-password` | POST | Yes | Re-encrypt vault with new key |
| `/vault` | GET | Yes | Dashboard page |
| `/api/entries` | GET | Yes | List all entries (`?q=` for search) |
| `/api/entries/<id>` | GET | Yes | Get single entry |
| `/api/entries` | POST | Yes | Add entry |
| `/api/entries/<id>` | PUT | Yes | Update entry |
| `/api/entries/<id>` | DELETE | Yes | Delete entry |
| `/api/generate` | GET | Yes | Generate password (`?len=&upper=&digits=&symbols=&noambig=`) |
| `/api/strength` | POST | Yes | Check password strength |
| `/api/export` | GET | Yes | Export vault as JSON |
| `/api/import` | POST | Yes | Import JSON entries |
| `/api/health` | GET | No | Health check |

---

## Development

```bash
pip install -e ".[dev]"

pytest -v                          # 32 tests, all passing
ruff check .                       # Lint
ruff format .                      # Format
mypy password_manager/             # Type check
```

---

## License

MIT — see [LICENSE](LICENSE).
