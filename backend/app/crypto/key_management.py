from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..core.config import PATHS, SETTINGS, KeyStatus
from ..core.exceptions import ForgeError
from .hashing import b64d, b64e
from .pqc import PQC, PQCProvider

IDENTITY_STORE = PATHS.keys / "identities.json"
WATERMARK_ROOT = PATHS.keys / "watermark_root.json"
SERVER_IDENTITY = PATHS.keys / "server_identity.json"

PASSENSPHRASE_ENV = "FORGE_MASTER_PASSPHRASE"
DEV_SECRET_FILE = PATHS.data / "master_secret.bin"


class KeyStoreError(ForgeError):
    status = 500
    code = "KEYSTORE_ERROR"


class MasterSecretMismatch(KeyStoreError):
    """The local secret no longer opens the stored key material. Recoverable only by
    restoring the original secret or discarding the instance, never by retrying."""

    status = 500
    code = "MASTER_SECRET_MISMATCH"


@dataclass
class KeyRecord:
    key_id: str
    owner_id: str
    purpose: str
    algorithm: str
    version: int
    status: str
    created_at: str
    expires_at: str | None
    public_key: str
    secret_key_nonce: str | None = None
    secret_key_ciphertext: str | None = None

    def public_metadata(self) -> dict[str, Any]:
        """Deliberately omits every private-key field so this can be exposed
        through the API and the frontend without an extra filter."""
        return {
            "key_id": self.key_id,
            "owner_id": self.owner_id,
            "purpose": self.purpose,
            "algorithm": self.algorithm,
            "version": self.version,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "public_key": self.public_key,
        }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(moment: datetime | None) -> str | None:
    return moment.isoformat(timespec="seconds") if moment else None


def _restrict(path: Path) -> None:
    if os.name == "nt":
        # Windows has no POSIX mode bits; ACL hardening is a deployment concern
        # and is called out in docs/prototype-vs-production.md instead.
        return
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def load_master_secret() -> bytes:
    """Returns the root secret that protects every private key at rest.

    Development path: a passphrase from the environment, or a generated local
    secret file. Production replaces this whole function with an HSM/KMS call
    that never returns plaintext key material to the process.
    """
    passphrase = os.getenv(PASSENSPHRASE_ENV)
    if passphrase:
        return _derive_kek(passphrase.encode("utf-8"), salt=b"forge-master-static")

    if DEV_SECRET_FILE.exists():
        return DEV_SECRET_FILE.read_bytes()

    # Generating a fresh secret over an existing key store would leave every
    # already-issued key permanently undecryptable, and the only symptom would be
    # an InvalidTag deep inside AES-GCM. Refuse before generating anything.
    if IDENTITY_STORE.exists() or WATERMARK_ROOT.exists():
        raise MasterSecretMismatch(
            "The key store holds issued keys but data/master_secret.bin is missing, so "
            "none of them can ever be decrypted again. Restore the original secret file, "
            "or wipe data/, keys/, ledger/ and evidence/ together to start a clean instance."
        )

    DEV_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    secret = os.urandom(32)
    DEV_SECRET_FILE.write_bytes(secret)
    _restrict(DEV_SECRET_FILE)
    return secret


def _derive_kek(passphrase: bytes, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt,
        length=32,
        n=SETTINGS.scrypt_n,
        r=SETTINGS.scrypt_r,
        p=SETTINGS.scrypt_p,
    ).derive(passphrase)


def _aes_wrap(kek: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    blob = AESGCM(kek).encrypt(nonce, plaintext, aad)
    return nonce, blob


def _aes_unwrap(kek: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(kek).decrypt(nonce, ciphertext, aad)


class KeyVault:
    """Encrypted local key storage. Private keys never leave this object in
    plaintext except through the narrow call sites that need to sign or
    decapsulate."""

    def __init__(self, provider: PQCProvider | None = None):
        self.provider = provider or PQC
        self._kek = load_master_secret()
        self._records: dict[str, dict[str, KeyRecord]] = {}
        self._watermark_root: bytes | None = None
        self._load()

    # ---- persistence -------------------------------------------------------

    def _load(self) -> None:
        if IDENTITY_STORE.exists():
            raw = json.loads(IDENTITY_STORE.read_text(encoding="utf-8"))
            self._records = {
                owner: {purpose: KeyRecord(**fields) for purpose, fields in purposes.items()}
                for owner, purposes in raw.items()
            }
        if WATERMARK_ROOT.exists():
            blob = json.loads(WATERMARK_ROOT.read_text(encoding="utf-8"))
            self._watermark_root = self._unwrap_or_die(
                b64d(blob["nonce"]), b64d(blob["ciphertext"]), b"forge:watermark-root:v1"
            )

    def _unwrap_or_die(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        try:
            return _aes_unwrap(self._kek, nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise MasterSecretMismatch(
                "A stored key could not be unwrapped with the current master secret. "
                "The secret does not match the one this key store was written with; "
                "restore the original data/master_secret.bin or the SENTINEL_PASSPHRASE "
                "environment variable."
            ) from exc

    def _persist(self) -> None:
        payload = {
            owner: {purpose: asdict(record) for purpose, record in purposes.items()}
            for owner, purposes in self._records.items()
        }
        IDENTITY_STORE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        _restrict(IDENTITY_STORE)

    # ---- issuance ----------------------------------------------------------

    def issue_identity(self, owner_id: str, *, ttl_days: int = 365) -> dict[str, KeyRecord]:
        signing = self.provider.generate_signing_keypair()
        kem = self.provider.generate_kem_keypair()
        created = _now()
        expires = created + timedelta(days=ttl_days)
        meta = self.provider.metadata

        signing_record = self._store_secret(
            KeyRecord(
                key_id=f"{owner_id}-SIG-{meta.signing_algorithm}",
                owner_id=owner_id,
                purpose="SIGNING",
                algorithm=meta.signing_algorithm,
                version=1,
                status=KeyStatus.ACTIVE,
                created_at=_stamp(created) or "",
                expires_at=_stamp(expires),
                public_key=b64e(signing.public_key),
            ),
            signing.secret_key,
        )
        kem_record = self._store_secret(
            KeyRecord(
                key_id=f"{owner_id}-KEM-{meta.kem_algorithm}",
                owner_id=owner_id,
                purpose="KEM",
                algorithm=meta.kem_algorithm,
                version=1,
                status=KeyStatus.ACTIVE,
                created_at=_stamp(created) or "",
                expires_at=_stamp(expires),
                public_key=b64e(kem.public_key),
            ),
            kem.secret_key,
        )
        self._persist()
        return {"signing": signing_record, "kem": kem_record}

    def _store_secret(self, record: KeyRecord, secret: bytes) -> KeyRecord:
        aad = f"forge:key:{record.owner_id}:{record.purpose}:v{record.version}".encode()
        nonce, blob = _aes_wrap(self._kek, secret, aad)
        record.secret_key_nonce = b64e(nonce)
        record.secret_key_ciphertext = b64e(blob)
        self._records.setdefault(record.owner_id, {})[record.purpose] = record
        return record

    def rotate_signing_key(self, owner_id: str) -> KeyRecord:
        existing = self._records.get(owner_id, {}).get("SIGNING")
        if existing:
            existing.status = KeyStatus.ROTATED
        fresh = self.provider.generate_signing_keypair()
        meta = self.provider.metadata
        version = (existing.version + 1) if existing else 1
        record = self._store_secret(
            KeyRecord(
                key_id=f"{owner_id}-SIG-{meta.signing_algorithm}-v{version}",
                owner_id=owner_id,
                purpose="SIGNING",
                algorithm=meta.signing_algorithm,
                version=version,
                status=KeyStatus.ACTIVE,
                created_at=_stamp(_now()) or "",
                expires_at=_stamp(_now() + timedelta(days=365)),
                public_key=b64e(fresh.public_key),
            ),
            fresh.secret_key,
        )
        self._persist()
        return record

    def set_status(self, owner_id: str, purpose: str, status: str) -> None:
        record = self._records.get(owner_id, {}).get(purpose)
        if record is None:
            raise KeyStoreError(f"No {purpose} key for {owner_id}")
        record.status = status
        self._persist()

    # ---- consumption -------------------------------------------------------

    def _secret(self, owner_id: str, purpose: str, *, require_active: bool = True) -> bytes:
        record = self._records.get(owner_id, {}).get(purpose)
        if record is None:
            raise KeyStoreError(f"No {purpose} key issued to {owner_id}")
        if require_active and record.status not in (KeyStatus.ACTIVE, KeyStatus.EXPIRING):
            raise KeyStoreError(
                f"{purpose} key for {owner_id} is {record.status}; signing is not permitted"
            )
        aad = f"forge:key:{owner_id}:{purpose}:v{record.version}".encode()
        return _aes_unwrap(
            self._kek,
            b64d(record.secret_key_nonce or ""),
            b64d(record.secret_key_ciphertext or ""),
            aad,
        )

    def signing_public_key(self, owner_id: str) -> bytes:
        record = self._records.get(owner_id, {}).get("SIGNING")
        if record is None:
            raise KeyStoreError(f"No signing key issued to {owner_id}")
        return b64d(record.public_key)

    def kem_public_key(self, owner_id: str) -> bytes:
        record = self._records.get(owner_id, {}).get("KEM")
        if record is None:
            raise KeyStoreError(f"No KEM key issued to {owner_id}")
        return b64d(record.public_key)

    def sign_as(self, owner_id: str, message: bytes, context: bytes) -> bytes:
        return self.provider.sign(self._secret(owner_id, "SIGNING"), message, context).raw

    def verify_as(self, owner_id: str, message: bytes, signature: bytes, context: bytes) -> bool:
        return self.provider.verify(self.signing_public_key(owner_id), message, signature, context)

    def decapsulate_for(self, owner_id: str, ciphertext: bytes) -> bytes:
        return self.provider.decapsulate(self._secret(owner_id, "KEM"), ciphertext)

    def signing_secret_for(self, owner_id: str) -> bytes:
        """Signing key material for in-process use.

        Exposed deliberately and narrowly: signature, decapsulation and node
        voting all need the raw key, and every one of those call sites is inside
        the trusted boundary of this process. It is never reachable through the
        API, the database or the frontend.
        """
        return self._secret(owner_id, "SIGNING")

    def public_metadata(self, owner_id: str | None = None) -> list[dict[str, Any]]:
        owners = [owner_id] if owner_id else list(self._records)
        out: list[dict[str, Any]] = []
        for owner in owners:
            for record in self._records.get(owner, {}).values():
                out.append(record.public_metadata())
        return out

    # ---- watermark root secret --------------------------------------------

    def watermark_root(self) -> bytes:
        """The watermark derivation key. Without it an extracted tag cannot be
        turned back into a recipient, session or document."""
        if self._watermark_root is None:
            self._watermark_root = os.urandom(32)
            nonce, blob = _aes_wrap(self._kek, self._watermark_root, b"forge:watermark-root:v1")
            WATERMARK_ROOT.write_text(
                json.dumps({"nonce": b64e(nonce), "ciphertext": b64e(blob)}, indent=2),
                encoding="utf-8",
            )
            _restrict(WATERMARK_ROOT)
        return self._watermark_root

    def storage_report(self) -> dict[str, Any]:
        return {
            "private_keys_at_rest": "AES-256-GCM under a scrypt-derived key-encryption-key",
            "master_secret_source": (
                "environment passphrase"
                if os.getenv(PASSENSPHRASE_ENV)
                else "generated local file (DEVELOPMENT ONLY)"
            ),
            "keystore_path": str(IDENTITY_STORE),
            "identities_held": sorted(self._records),
            "production_requirement": (
                "Replace with HSM/KMS-backed non-exportable keys; the local file store is a "
                "prototype convenience and offers no protection against an attacker who has "
                "already compromised the host."
            ),
        }


VAULT = KeyVault()


def derive_wrapping_key(shared_secret: bytes, *context: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"|".join(part.encode("utf-8") for part in context),
    ).derive(shared_secret)
