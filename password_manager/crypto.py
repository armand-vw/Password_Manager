import os
import base64
import secrets
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

VERIFICATION_STRING = "MASTER_VERIFIED_OK"
SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32


def generate_salt() -> bytes:
    """Generate a cryptographically secure random 16-byte salt."""
    return os.urandom(SALT_LENGTH)


def derive_key(master_password: str, salt: bytes, iterations: int = 600_000) -> bytes:
    """
    Derive a 32-byte AES-256 key from the master password using PBKDF2HMAC.

    Uses SHA-256 and 600,000+ iterations to resist brute-force. The salt
    ensures identical passwords produce unique keys.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_password(key: bytes, plaintext: str) -> "tuple[str, str]":
    """
    Encrypt plaintext using AES-256-GCM with a fresh 12-byte nonce.

    Returns (base64_ciphertext, base64_nonce). A unique nonce per
    operation prevents nonce-reuse attacks.
    """
    nonce = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return (
        base64.b64encode(ciphertext).decode("utf-8"),
        base64.b64encode(nonce).decode("utf-8"),
    )


def decrypt_password(key: bytes, ciphertext_b64: str, nonce_b64: str) -> str:
    """
    Decrypt a base64-encoded AES-256-GCM ciphertext.

    Raises InvalidTag if the key is wrong or the data was tampered with.
    """
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def password_strength(password: str) -> "dict":
    """
    Estimate password strength and return a score + feedback.

    Measures: length, character variety (lowercase, uppercase,
    digits, symbols) and checks against common weak patterns.
    """
    score = 0
    feedback: list[str] = []

    if len(password) < 8:
        feedback.append("Too short (minimum 8 characters)")
    elif len(password) >= 16:
        score += 2
        feedback.append("Good length")
    elif len(password) >= 12:
        score += 1
    else:
        feedback.append("Consider making it longer (12+ characters)")

    charset_checks = [
        (lambda p: any(c.islower() for c in p), "lowercase"),
        (lambda p: any(c.isupper() for c in p), "uppercase"),
        (lambda p: any(c.isdigit() for c in p), "digits"),
        (lambda p: any(not c.isalnum() for c in p), "symbols"),
    ]
    charsets_used = sum(1 for check, _ in charset_checks if check(password))
    if charsets_used <= 1:
        feedback.append("Use a mix of character types")
    score += charsets_used

    common_words = ["password", "123456", "qwerty", "admin", "letmein"]
    pw_lower = password.lower()
    for word in common_words:
        if word in pw_lower:
            score -= 2
            feedback.append(f"Avoid common words like '{word}'")
            break

    # clamp
    score = max(0, min(score, 5))

    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong", 5: "Very Strong"}
    return {
        "score": score,
        "label": labels.get(score, "Unknown"),
        "feedback": feedback,
    }


def generate_password(length: int = 24, uppercase: bool = True,
                      digits: bool = True, symbols: bool = True,
                      exclude_ambiguous: bool = False) -> str:
    """Generate a cryptographically secure random password."""
    import string
    chars = string.ascii_lowercase
    if uppercase:
        chars += string.ascii_uppercase
    if digits:
        chars += string.digits
    if symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if exclude_ambiguous:
        for c in "Il1O0":
            chars = chars.replace(c, "")
    if not chars:
        chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))
