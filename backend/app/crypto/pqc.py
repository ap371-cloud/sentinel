from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.exceptions import ForgeError

#: Domain separation contexts. ML-DSA authenticates these into the signature so a
#: signature minted for a decryption event can never be replayed as, say, a
#: ledger block vote.
CTX_DECRYPTION_EVENT = b"FORGE/decryption-event/v1"
CTX_LEDGER_BLOCK = b"FORGE/ledger-block/v1"
CTX_LEDGER_VOTE = b"FORGE/ledger-vote/v1"
CTX_SESSION_ATTESTATION = b"FORGE/session-attestation/v1"

DEVELOPMENT_ONLY_BACKEND = "REFERENCE-IMPL-DEV-ONLY"


class PQCUnavailable(ForgeError):
    code = "PQC_BACKEND_UNAVAILABLE"
    plain_explanation = "No NIST post-quantum backend is installed in this environment."


@dataclass(frozen=True)
class Keypair:
    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class Signature:
    raw: bytes
    algorithm: str


@dataclass(frozen=True)
class Encapsulation:
    ciphertext: bytes
    shared_secret: bytes


@dataclass(frozen=True)
class PQCMetadata:
    signing_algorithm: str
    kem_algorithm: str
    backend_library: str
    backend_module: str
    production_grade: bool
    public_key_bytes: int
    secret_key_bytes: int
    signature_bytes: int
    kem_public_key_bytes: int
    kem_ciphertext_bytes: int
    kem_shared_secret_bytes: int
    limitations: tuple[str, ...]


class PQCProvider:
    """Thin, explicit wrapper over NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).

    No algorithm is implemented here. Every operation is delegated to
    ``pqcrypto`` 1.0.0, which ships PQClean reference code compiled into a
    single extension module.
    """

    def __init__(self, signing_module: str = "ml_dsa_65", kem_module: str = "ml_kem_768"):
        self.signing_module = signing_module
        self.kem_module = kem_module
        self._sign = None
        self._kem = None
        self._load_error: str | None = None
        self._load()

    def _load(self) -> None:
        try:
            import pqcrypto.sign as sign_pkg
            import pqcrypto.kem as kem_pkg
        except Exception as exc:  # pragma: no cover - depends on environment
            self._load_error = f"pqcrypto import failed: {exc}"
            return
        self._sign = getattr(sign_pkg, self.signing_module, None)
        self._kem = getattr(kem_pkg, self.kem_module, None)
        if self._sign is None or self._kem is None:
            self._load_error = (
                f"pqcrypto present but missing {self.signing_module}/{self.kem_module}"
            )

    @property
    def available(self) -> bool:
        return self._sign is not None and self._kem is not None

    def _require(self) -> None:
        if not self.available:
            raise PQCUnavailable(
                "Post-quantum backend unavailable. Install pqcrypto>=1.0.0, or accept a "
                "clearly labelled reference implementation.",
                detail=self._load_error or "",
            )

    # ---- ML-DSA (FIPS 204) -------------------------------------------------

    def generate_signing_keypair(self) -> Keypair:
        self._require()
        public_key, secret_key = self._sign.keygen()
        return Keypair(public_key=public_key, secret_key=secret_key)

    def sign(self, secret_key: bytes, message: bytes, context: bytes = CTX_DECRYPTION_EVENT) -> Signature:
        self._require()
        raw = self._sign.sign(secret_key, message, context=context)
        return Signature(raw=raw, algorithm=self.metadata.signing_algorithm)

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        context: bytes = CTX_DECRYPTION_EVENT,
    ) -> bool:
        self._require()
        try:
            self._sign.verify(public_key, message, signature, context=context)
        except Exception:
            return False
        return True

    # ---- ML-KEM (FIPS 203) -------------------------------------------------

    def generate_kem_keypair(self) -> Keypair:
        self._require()
        public_key, secret_key = self._kem.keygen()
        return Keypair(public_key=public_key, secret_key=secret_key)

    def encapsulate(self, kem_public_key: bytes) -> Encapsulation:
        self._require()
        ciphertext, shared_secret = self._kem.encaps(kem_public_key)
        return Encapsulation(ciphertext=ciphertext, shared_secret=shared_secret)

    def decapsulate(self, kem_secret_key: bytes, ciphertext: bytes) -> bytes:
        self._require()
        return self._kem.decaps(kem_secret_key, ciphertext)

    # ---- metadata ----------------------------------------------------------

    @property
    def metadata(self) -> PQCMetadata:
        if self.available:
            sign_alg = self._sign.ALGORITHM
            kem_alg = self._kem.ALGORITHM
            limitations = (
                "Prototype runs the compiled PQClean implementation inside a single "
                "process with no HSM or FIPS-140 validation boundary.",
                "Key material is protected by a local passphrase-derived KEK only; "
                "production requires hardware-backed storage.",
            )
            production_grade = True
            backend_library = "pqcrypto 1.0.0 (PQClean-derived, liboqs API)"
            backend_module = f"pqcrypto.sign.{self.signing_module} / pqcrypto.kem.{self.kem_module}"
            sizes = dict(
                public_key_bytes=self._sign.PUBLIC_KEY_SIZE,
                secret_key_bytes=self._sign.SECRET_KEY_SIZE,
                signature_bytes=self._sign.SIGNATURE_SIZE,
                kem_public_key_bytes=self._kem.PUBLIC_KEY_SIZE,
                kem_ciphertext_bytes=self._kem.CIPHERTEXT_SIZE,
                kem_shared_secret_bytes=self._kem.SHARED_SECRET_SIZE,
            )
        else:
            sign_alg = f"ML-DSA-65 ({DEVELOPMENT_ONLY_BACKEND})"
            kem_alg = f"ML-KEM-768 ({DEVELOPMENT_ONLY_BACKEND})"
            limitations = (
                "No compiled post-quantum backend is installed. Every signature and "
                "key agreement performed here is NOT cryptographically protected.",
                "Replace with an approved FIPS 203/204 implementation before any use "
                "beyond local demonstration.",
            )
            production_grade = False
            backend_library = DEVELOPMENT_ONLY_BACKEND
            backend_module = "unavailable"
            sizes = dict.fromkeys(
                (
                    "public_key_bytes",
                    "secret_key_bytes",
                    "signature_bytes",
                    "kem_public_key_bytes",
                    "kem_ciphertext_bytes",
                    "kem_shared_secret_bytes",
                ),
                0,
            )
        return PQCMetadata(
            signing_algorithm=sign_alg,
            kem_algorithm=kem_alg,
            backend_library=backend_library,
            backend_module=backend_module,
            production_grade=production_grade,
            limitations=limitations,
            **sizes,
        )

    def describe(self) -> dict[str, Any]:
        meta = self.metadata
        return {
            "signing_algorithm": meta.signing_algorithm,
            "kem_algorithm": meta.kem_algorithm,
            "backend_library": meta.backend_library,
            "backend_module": meta.backend_module,
            "production_grade_backend": meta.production_grade,
            "domain_separation_contexts": [
                CTX_DECRYPTION_EVENT.decode(),
                CTX_LEDGER_BLOCK.decode(),
                CTX_LEDGER_VOTE.decode(),
                CTX_SESSION_ATTESTATION.decode(),
            ],
            "limitations": list(meta.limitations),
        }


PQC = PQCProvider()
