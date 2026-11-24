"""
Secret box - encrypts the login password/cookie of a scan while it waits in the queue.

The web app and the worker are separate programs, so the worker can only get
the password through the database. We never store it in plain text: it is
encrypted with Fernet (from the "cryptography" library, AES + a signature)
using a key made from the app's secret key. The worker decrypts it once and
the database copy is wiped straight away.
"""

import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken

from config.secret_key import get_secret_key


def _fernet():
    # Fernet needs a 32-byte key in base64. We derive it from the secret key.
    digest = hashlib.sha256(("webvuln-secrets:" + get_secret_key()).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secrets(secrets_dict):
    """Return encrypted text, or "" when there is nothing secret to store."""
    if not any(secrets_dict.values()):
        return ""
    return _fernet().encrypt(json.dumps(secrets_dict).encode()).decode()


def decrypt_secrets(token):
    if not token:
        return {}
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except (InvalidToken, ValueError):
        return {}
