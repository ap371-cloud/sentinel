from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import time
from dataclasses import dataclass
from typing import Any

from ..core.config import SETTINGS
from .exceptions import AuthenticationError, OfflinePolicyViolation
from ..crypto.hashing import b64d, b64e, canonical_bytes

TOKEN_TTL_SECONDS = 8 * 3600
PBKDF2_ALGORITHM = "pbkdf2_sha256"


def hash_password(password: str, *, salt: bytes | None = None, iterations: int | None = None) -> tuple[str, str]:
    salt = salt or os.urandom(16)
    rounds = iterations or SETTINGS.pbkdf2_iterations
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds, dklen=32)
    return f"{PBKDF2_ALGORITHM}${rounds}${b64e(salt)}${b64e(derived)}", b64e(salt)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, rounds, salt_b64, hash_b64 = stored_hash.split("$")
        if algorithm != PBKDF2_ALGORITHM:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), b64d(salt_b64), int(rounds), dklen=32
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, b64d(hash_b64))


@dataclass(frozen=True)
class TokenClaims:
    subject: str
    role: str
    unit: str
    clearance: int
    issued_at: int
    expires_at: int
    token_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sub": self.subject,
            "role": self.role,
            "unit": self.unit,
            "clr": self.clearance,
            "iat": self.issued_at,
            "exp": self.expires_at,
            "jti": self.token_id,
        }


class TokenIssuer:
    """Locally signed bearer tokens. Every decryption still re-reads account
    state from the database, so revoking a recipient invalidates access
    immediately even though the token itself has not expired."""

    def __init__(self, secret: bytes | None = None):
        self._secret = secret or hashlib.sha256(b"forge-token-signing:" + os.urandom(32)).digest()

    def issue(self, *, subject: str, role: str, unit: str, clearance: int, ttl: int = TOKEN_TTL_SECONDS) -> str:
        now = int(time.time())
        claims = TokenClaims(
            subject=subject,
            role=role,
            unit=unit,
            clearance=clearance,
            issued_at=now,
            expires_at=now + ttl,
            token_id=b64e(os.urandom(9)),
        )
        body = b64e(canonical_bytes(claims.to_dict()))
        return f"{body}.{b64e(self._mac(body))}"

    def read(self, token: str) -> TokenClaims:
        try:
            body, signature = token.split(".", 1)
        except ValueError as exc:
            raise AuthenticationError("Malformed authentication token.") from exc
        if not hmac.compare_digest(b64d(signature), self._mac(body.encode("ascii"))):
            raise AuthenticationError("Token signature did not verify.")
        claims = json.loads(b64d(body))
        if int(claims["exp"]) < int(time.time()):
            raise AuthenticationError("Authentication token has expired.")
        return TokenClaims(
            subject=claims["sub"],
            role=claims["role"],
            unit=claims["unit"],
            clearance=int(claims["clr"]),
            issued_at=int(claims["iat"]),
            expires_at=int(claims["exp"]),
            token_id=claims["jti"],
        )

    def _mac(self, body: str | bytes) -> bytes:
        raw = body.encode("ascii") if isinstance(body, str) else body
        return hmac.new(self._secret, raw, hashlib.sha256).digest()


TOKENS = TokenIssuer()


class EgressGuard:
    """Enforces the air-gap at runtime instead of merely claiming it.

    Loopback is allowed because the command terminal talks to this process over
    127.0.0.1. Every other destination raises, which means a code path that
    tries to phone home fails loudly and generates a policy-violation event
    rather than silently leaking a document.
    """

    ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost"}

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.violations: list[dict[str, Any]] = []
        self._installed = False

    def install(self) -> None:
        if not self.enabled or self._installed:
            return
        guard = self

        original_connect = socket.socket.connect
        original_connect_ex = socket.socket.connect_ex
        original_create = socket.create_connection

        def _host_of(address: Any) -> str:
            if isinstance(address, tuple) and address:
                return str(address[0])
            return str(address)

        def checked(original):
            def wrapper(self_sock, address, *args, **kwargs):
                host = _host_of(address)
                if host not in guard.ALLOWED_HOSTS:
                    guard.record(host)
                    raise OfflinePolicyViolation(
                        f"Blocked outbound connection to {host}",
                        detail="AIR-GAPPED MODE is active; only loopback traffic is permitted.",
                    )
                return original(self_sock, address, *args, **kwargs)

            return wrapper

        def checked_create(address, *args, **kwargs):
            host = _host_of(address)
            if host not in guard.ALLOWED_HOSTS:
                guard.record(host)
                raise OfflinePolicyViolation(
                    f"Blocked outbound connection to {host}",
                    detail="AIR-GAPPED MODE is active; only loopback traffic is permitted.",
                )
            return original_create(address, *args, **kwargs)

        socket.socket.connect = checked(original_connect)
        socket.socket.connect_ex = checked(original_connect_ex)
        socket.create_connection = checked_create
        self._installed = True

    def record(self, host: str) -> None:
        self.violations.append({"host": host, "at": time.time()})
        SETTINGS.violation_log.append(host)

    def status(self) -> dict[str, Any]:
        return {
            "air_gapped_mode": "ACTIVE" if self.enabled else "DISABLED",
            "guard_installed": self._installed,
            "allowed_hosts": sorted(self.ALLOWED_HOSTS),
            "blocked_attempts": len(self.violations),
            "blocked_targets": sorted({v["host"] for v in self.violations}),
            "external_services_used": [],
            "plain_explanation": (
                "The system refuses every network connection except the local command terminal."
            ),
        }


EGRESS = EgressGuard(SETTINGS.air_gapped)
