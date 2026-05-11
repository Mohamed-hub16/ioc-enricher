"""AES-128-GCM encryption for user API keys stored in the database."""
import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _key() -> bytes:
    """Derive a stable 128-bit key from the application's SECRET_KEY."""
    return hashlib.sha256(os.getenv("SECRET_KEY", "").encode()).digest()[:16]


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    nonce = os.urandom(12)
    ct = AESGCM(_key()).encrypt(nonce, plaintext.encode(), None)
    return base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        raw = base64.urlsafe_b64decode(ciphertext.encode())
        return AESGCM(_key()).decrypt(raw[:12], raw[12:], None).decode()
    except Exception:
        return ""
