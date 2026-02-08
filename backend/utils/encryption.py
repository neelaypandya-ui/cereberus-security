"""Fernet encryption utility for API key storage."""

import base64
import hashlib

from cryptography.fernet import Fernet


def derive_key(secret: str) -> bytes:
    """Derive a Fernet key from a secret string."""
    key = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(key)


def encrypt_value(value: str, secret: str) -> str:
    """Encrypt a plaintext value using the derived Fernet key."""
    f = Fernet(derive_key(secret))
    return f.encrypt(value.encode()).decode()


def decrypt_value(encrypted: str, secret: str) -> str:
    """Decrypt an encrypted value using the derived Fernet key."""
    f = Fernet(derive_key(secret))
    return f.decrypt(encrypted.encode()).decode()
