"""At-rest encryption of provider API keys (Fernet, keyed by PF_SECRET_KEY).

Unlike the lab secrets (deterministic from population.seed by design, see
CLAUDE.md), LLM API keys are real third-party credentials: they're encrypted
in the DB and never returned by the API once stored.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

MIN_SECRET_LEN = 32


class SecretKeyMissing(RuntimeError):
    pass


class SecretCipher:
    def __init__(self, secret_key: str | None) -> None:
        if not secret_key or len(secret_key) < MIN_SECRET_LEN:
            raise SecretKeyMissing(
                f"PF_SECRET_KEY must be set (>= {MIN_SECRET_LEN} random chars) to store provider API keys; "
                'generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        # Accept any high-entropy string; derive the 32-byte Fernet key from it.
        digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("cannot decrypt stored API key (PF_SECRET_KEY changed?)") from exc
