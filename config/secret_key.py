"""
The app's secret key.

It is used to sign the login cookie (so nobody can fake being logged in) and
to encrypt scan passwords while a scan waits in the queue.

  * Public mode: the key MUST be given in the WEBVULN_SECRET_KEY environment
    variable, so every web and worker process uses the same key.
  * Local mode: if no key is given, a random one is created once and saved in
    instance/secret_key (that folder is ignored by git).
"""

import os
import secrets

from config import settings

_cached_key = None


def get_secret_key():
    global _cached_key
    if settings.SECRET_KEY:
        return settings.SECRET_KEY
    if _cached_key:
        return _cached_key
    if settings.PUBLIC_MODE:
        raise RuntimeError(
            "WEBVULN_SECRET_KEY must be set in public mode. Create one with:\n"
            "  python -c \"import secrets; print(secrets.token_hex(32))\"")

    key_file = os.path.join(settings.INSTANCE_DIR, "secret_key")
    if os.path.exists(key_file):
        with open(key_file, encoding="utf-8") as file:
            _cached_key = file.read().strip()
    if not _cached_key:
        os.makedirs(settings.INSTANCE_DIR, exist_ok=True)
        _cached_key = secrets.token_hex(32)
        with open(key_file, "w", encoding="utf-8") as file:
            file.write(_cached_key)
    return _cached_key
