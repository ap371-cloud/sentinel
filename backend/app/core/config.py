from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Clearance(IntEnum):
    """Application-level prototype labels only. These do not reproduce any real
    government classification framework and carry no certification."""

    UNCLASSIFIED = 0
    RESTRICTED = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4

    @property
    def label(self) -> str:
        return self.name.replace("_", " ")


CLASSIFICATIONS = tuple(level.name for level in Clearance)
CLEARIFICATIONS = CLASSIFICATIONS


class Role:
    """Least privilege by construction. No role holds administrative power
    together with evidence, ledger or approval authority, so one compromised
    account cannot rewrite the record of what it did."""

    COMMANDER = "COMMANDER"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    DOCUMENT_ADMIN = "DOCUMENT_ADMIN"
    SENDER = "SENDER"
    RECIPIENT = "RECIPIENT"
    INVESTIGATOR = "INVESTIGATOR"
    LEDGER_OPERATOR = "LEDGER_OPERATOR"
    AUDITOR = "AUDITOR"

    ALL = (
        COMMANDER,
        SECURITY_OFFICER,
        DOCUMENT_ADMIN,
        SENDER,
        RECIPIENT,
        INVESTIGATOR,
        LEDGER_OPERATOR,
        AUDITOR,
    )

    APPROVERS = (COMMANDER, SECURITY_OFFICER)
    LOCKDOWN_AUTHORITIES = (COMMANDER, SECURITY_OFFICER)
    READ_ONLY = (AUDITOR,)


class DeviceAccessPolicy:
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_SECOND_APPROVAL = "REQUIRE_SECOND_APPROVAL"


class DeviceTrust:
    TRUSTED = "TRUSTED"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"
    REVOKED = "REVOKED"
    PENDING = "PENDING"


class AccountStatus:
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class KeyStatus:
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    EXPIRING = "EXPIRING"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"
    ARCHIVED = "ARCHIVED"


class DocumentLifecycle:
    CREATED = "CREATED"
    CLASSIFIED = "CLASSIFIED"
    APPROVED = "APPROVED"
    DISTRIBUTED = "DISTRIBUTED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    ARCHIVED = "ARCHIVED"

    ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
        CREATED: (CLASSIFIED, ARCHIVED),
        CLASSIFIED: (APPROVED, ARCHIVED),
        APPROVED: (DISTRIBUTED, ARCHIVED),
        DISTRIBUTED: (ACTIVE, REVOKED, ARCHIVED),
        ACTIVE: (EXPIRED, REVOKED, ARCHIVED),
        EXPIRED: (ARCHIVED,),
        REVOKED: (ARCHIVED,),
        ARCHIVED: (),
    }


class DocumentAccess:
    """Availability of the decrypted artefact, kept separate from whether
    decryption is authorised at all."""

    DRAFT = "DRAFT"
    SEALED = "SEALED"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class CaseStatus:
    OPEN = "OPEN"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    VERIFIED = "VERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"
    CLOSED = "CLOSED"


class Severity:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}


class ForensicOutcome:
    VERIFIED_ASSOCIATION = "VERIFIED ASSOCIATION"
    PARTIALLY_VERIFIED = "PARTIALLY VERIFIED"
    DOCUMENT_MODIFIED = "DOCUMENT MODIFIED"
    WATERMARK_NOT_RECOVERED = "WATERMARK NOT RECOVERED"
    SIGNATURE_INVALID = "SIGNATURE INVALID"
    LEDGER_PROOF_INVALID = "LEDGER PROOF INVALID"
    NO_MATCH_FOUND = "NO MATCH FOUND"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT EVIDENCE"

    OUTCOME_EXPLANATIONS = {
        VERIFIED_ASSOCIATION: (
            "Every link in the evidence chain verified: watermark, session, recipient, document "
            "version, recipient signature and ledger inclusion."
        ),
        PARTIALLY_VERIFIED: (
            "Some links verified and at least one failed. The failing link is named in the report."
        ),
        DOCUMENT_MODIFIED: (
            "The recovered watermark points at a known session, but the file's content hash does "
            "not match the version that session received. The copy was altered after decryption."
        ),
        WATERMARK_NOT_RECOVERED: (
            "No usable watermark carrier energy was found. Treat as an unattributed copy."
        ),
        SIGNATURE_INVALID: (
            "The decryption event did not verify against the recipient's registered public key. "
            "The record cannot be attributed to that recipient."
        ),
        LEDGER_PROOF_INVALID: (
            "The ledger transaction or its Merkle proof did not verify, so the event is not "
            "anchored in tamper-evident history."
        ),
        NO_MATCH_FOUND: (
            "A watermark payload was recovered but no registered decryption session corresponds "
            "to it."
        ),
        INSUFFICIENT_EVIDENCE: (
            "The submitted file could not be analysed far enough to reach a conclusion."
        ),
    }


#: Operations that can never proceed on one person's word.
HIGH_RISK_ACTIONS = (
    "DOCUMENT_ACCESS_HIGH_CLASSIFICATION",
    "KEY_RECOVERY",
    "EMERGENCY_ACCESS",
    "SECURITY_POLICY_MODIFICATION",
    "LEDGER_NODE_ADMINISTRATION",
    "EVIDENCE_EXPORT",
    "IDENTITY_REVOCATION_CRITICAL",
)


@dataclass(frozen=True)
class Paths:
    root: Path = Path(os.getenv("SENTINEL_DATA_ROOT", str(PROJECT_ROOT)))

    @property
    def data(self) -> Path:
        return self.root / "data"

    @property
    def keys(self) -> Path:
        return self.root / "keys"

    @property
    def ledger(self) -> Path:
        return self.root / "ledger"

    @property
    def evidence(self) -> Path:
        return self.root / "evidence"

    @property
    def uploads(self) -> Path:
        return self.data / "uploads"

    @property
    def sealed(self) -> Path:
        return self.data / "sealed"

    @property
    def render(self) -> Path:
        return self.data / "render"

    @property
    def backup(self) -> Path:
        return self.data / "backup"

    @property
    def ledger_nodes(self) -> tuple[str, ...]:
        return ("NODE-A", "NODE-B", "NODE-C")

    def ensure(self) -> "Paths":
        for folder in (
            self.data,
            self.keys,
            self.ledger,
            self.evidence,
            self.uploads,
            self.sealed,
            self.render,
            self.backup,
        ):
            folder.mkdir(parents=True, exist_ok=True)
        return self


PATHS = Paths().ensure()


@dataclass
class Settings:
    app_name: str = "SENTINEL — Secure Command Document Intelligence & Forensic Attribution"
    short_name: str = "SENTINEL"

    #: The runtime egress guard blocks every non-loopback socket while true.
    air_gapped: bool = os.getenv("SENTINEL_AIR_GAPPED", "1") != "0"

    ledger_nodes: tuple[str, ...] = PATHS.ledger_nodes
    #: 2 of 3 must sign a block. Raising this to 3 of 3 trades availability for
    #: a stronger guarantee and is a deliberate deployment decision.
    quorum_size: int = 2

    watermark_dpi: int = 200
    watermark_version: str = "WM-1.0"
    policy_version: str = "POL-1.0"

    replay_window_seconds: int = 45
    session_single_use: bool = True

    break_glass_ttl_seconds: int = 900
    approval_ttl_seconds: int = 600

    pbkdf2_iterations: int = 240_000
    scrypt_n: int = 2 ** 15
    scrypt_r: int = 8
    scrypt_p: int = 1

    #: Calibrated by scripts/calibrate_watermark.py against a two-page synthetic
    #: brief. At these values the tag was recovered from all five tested
    #: transformations — clean, PDF re-save, JPEG quality 70, 50% downscale and
    #: 150% upscale — with a worst-case carrier-to-noise ratio of 4.2, at a cost
    #: of 37.0 dB PSNR and 0.967 SSIM against the original render.
    watermark_strength: float = float(os.getenv("SENTINEL_WM_STRENGTH", "0.03"))
    carriers_per_bit: int = int(os.getenv("SENTINEL_WM_CARRIERS", "512"))
    extraction_scales: tuple[float, ...] = (1.0, 0.5, 2.0, 1.5, 0.75)

    #: Carrier-to-noise ratio treated as a confident recovery. The clean case
    #: sits near 7 and the worst tested transformation near 4, so 3.0 keeps
    #: margin without ever reporting a weak match as certain.
    found_threshold: float = 3.0
    weak_threshold: float = 1.5
    match_hamming_limit: int = 6

    ollama_url: str = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
    ollama_model: str = os.getenv("SENTINEL_OLLAMA_MODEL", "llama3.1:8b")
    ollama_timeout_seconds: float = 20.0

    #: Hosts the egress guard refused, surfaced on the dashboard so a blocked
    #: attempt is visible to an operator instead of vanishing.
    violation_log: list[str] = field(default_factory=list)

    def pqc_library(self) -> str:
        return "pqcrypto 1.0.0 (PQClean-derived liboqs bindings)"


SETTINGS = Settings()
