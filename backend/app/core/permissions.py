from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import AccountStatus, Clearance, DeviceAccessPolicy, DocumentAccess, Role
from .exceptions import ApprovalRequired, AuthorizationDenied, DeviceNotAuthorized, LockdownActive, RecipientRevoked

DOC_READ = "document.read"
DOC_UPLOAD = "document.upload"
DOC_SEAL = "document.seal"
DOC_DECRYPT = "document.decrypt"
DOC_GRANT = "document.grant"
DOC_LIFECYCLE = "document.lifecycle"
RECIPIENT_CREATE = "recipient.create"
RECIPIENT_REVOKE = "recipient.revoke"
DEVICE_MANAGE = "device.manage"
KEY_MANAGE = "key.manage"
KEY_RECOVER = "key.recover"
LEDGER_READ = "ledger.read"
LEDGER_VERIFY = "ledger.verify"
LEDGER_ADMIN = "ledger.admin"
FORENSICS_ANALYZE = "forensics.analyze"
CASE_MANAGE = "investigation.manage"
EVIDENCE_READ = "evidence.read"
EVIDENCE_EXPORT = "evidence.export"
SECURITY_LOCKDOWN = "security.lockdown"
SECURITY_ALERT = "security.alert"
INCIDENT_MANAGE = "incident.manage"
POLICY_MODIFY = "policy.modify"
AUDIT_READ = "audit.read"
COMMAND_DASHBOARD = "commander.dashboard"
APPROVAL_REQUEST = "approval.request"
APPROVAL_DECIDE = "approval.decide"
BREAKGLASS_REQUEST = "breakglass.request"
BACKUP_MANAGE = "backup.manage"
AI_QUERY = "ai.query"

#: Role permissions.
#:
#: Two properties are deliberate and load-bearing:
#:   1. No role holds every permission.
#:   2. DOCUMENT_ADMIN — the role that manages identities and configuration —
#:      holds none of the powers over evidence, the ledger or approvals. A
#:      compromised administrator therefore cannot forge attribution, rewrite
#:      history, or approve its own request.
PERMISSIONS: dict[str, frozenset[str]] = {
    Role.COMMANDER: frozenset(
        {
            COMMAND_DASHBOARD,
            DOC_READ,
            APPROVAL_DECIDE,
            APPROVAL_REQUEST,
            SECURITY_LOCKDOWN,
            SECURITY_ALERT,
            INCIDENT_MANAGE,
            BREAKGLASS_REQUEST,
            LEDGER_READ,
            AUDIT_READ,
            EVIDENCE_READ,
            AI_QUERY,
        }
    ),
    Role.SECURITY_OFFICER: frozenset(
        {
            COMMAND_DASHBOARD,
            DOC_READ,
            APPROVAL_DECIDE,
            RECIPIENT_REVOKE,
            DEVICE_MANAGE,
            KEY_MANAGE,
            SECURITY_LOCKDOWN,
            SECURITY_ALERT,
            INCIDENT_MANAGE,
            BREAKGLASS_REQUEST,
            LEDGER_READ,
            EVIDENCE_READ,
            AUDIT_READ,
            APPROVAL_REQUEST,
            AI_QUERY,
        }
    ),
    Role.DOCUMENT_ADMIN: frozenset(
        {
            RECIPIENT_CREATE,
            DOC_READ,
            DEVICE_MANAGE,
            DOC_UPLOAD,
            DOC_SEAL,
            DOC_GRANT,
            DOC_LIFECYCLE,
            POLICY_MODIFY,
            APPROVAL_REQUEST,
            BREAKGLASS_REQUEST,
            BACKUP_MANAGE,
            AUDIT_READ,
            AI_QUERY,
        }
    ),
    Role.SENDER: frozenset({DOC_READ, DOC_UPLOAD, DOC_SEAL, DOC_GRANT, DOC_LIFECYCLE, LEDGER_READ}),
    Role.RECIPIENT: frozenset({DOC_READ, DOC_DECRYPT, LEDGER_READ, AI_QUERY}),
    Role.INVESTIGATOR: frozenset(
        {
            DOC_READ,
            FORENSICS_ANALYZE,
            CASE_MANAGE,
            EVIDENCE_READ,
            #: Holding export does not make it unilateral. The action is in
            #: TWO_PERSON_PERMISSIONS, so it can never complete on one identity.
            EVIDENCE_EXPORT,
            LEDGER_VERIFY,
            AUDIT_READ,
            AI_QUERY,
        }
    ),
    Role.LEDGER_OPERATOR: frozenset({DOC_READ, LEDGER_ADMIN, LEDGER_VERIFY, LEDGER_READ, AI_QUERY}),
    Role.AUDITOR: frozenset({DOC_READ, LEDGER_VERIFY, LEDGER_READ, EVIDENCE_READ, AUDIT_READ, COMMAND_DASHBOARD}),
}

#: Actions that can never proceed on one person's word.
TWO_PERSON_PERMISSIONS = frozenset(
    {EVIDENCE_EXPORT, LEDGER_ADMIN, POLICY_MODIFY, KEY_RECOVER, BREAKGLASS_REQUEST}
)

#: Permissions a read-only auditor is never granted, asserted here so a future
#: edit that adds one fails the test suite instead of quietly widening access.
AUDITOR_FORBIDDEN = frozenset(
    {
        RECIPIENT_CREATE, RECIPIENT_REVOKE, DEVICE_MANAGE, KEY_MANAGE, POLICY_MODIFY,
        DOC_UPLOAD, DOC_SEAL, DOC_GRANT, DOC_DECRYPT, DOC_LIFECYCLE,
        FORENSICS_ANALYZE, CASE_MANAGE, EVIDENCE_EXPORT, APPROVAL_DECIDE,
        SECURITY_LOCKDOWN, LEDGER_ADMIN, INCIDENT_MANAGE, BACKUP_MANAGE,
    }
)


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, frozenset())


def require_permission(role: str, permission: str) -> None:
    if not has_permission(role, permission):
        raise AuthorizationDenied(
            f"Role {role} is not permitted to perform {permission}.",
            detail="Separation of duties: this action belongs to a different role.",
        )


def require_writable(role: str) -> None:
    """Read-only roles are blocked before any handler runs rather than relying on
    each route to remember."""
    if role in Role.READ_ONLY:
        raise AuthorizationDenied(
            f"{role} is a read-only role and cannot modify any record.",
            detail="An auditor may verify evidence but never alter it.",
        )


def separation_of_duties_report() -> list[dict[str, Any]]:
    return [
        {
            "role": role,
            "permission_count": len(perms),
            "permissions": sorted(perms),
            "read_only": role in Role.READ_ONLY,
            "holds_evidence_authority": bool(perms & {FORENSICS_ANALYZE, CASE_MANAGE, EVIDENCE_EXPORT}),
            "holds_ledger_write_authority": LEDGER_ADMIN in perms,
            "holds_approval_authority": APPROVAL_DECIDE in perms,
            "holds_identity_administration": RECIPIENT_CREATE in perms,
        }
        for role, perms in sorted(PERMISSIONS.items())
    ]


@dataclass
class Check:
    name: str
    passed: bool
    reason_code: str
    plain_explanation: str


@dataclass
class Decision:
    allowed: bool
    reason_code: str
    plain_explanation: str
    checks: list[Check] = field(default_factory=list)
    requires_second_approval: bool = False

    def trace(self) -> list[dict[str, Any]]:
        return [
            {
                "check": c.name,
                "passed": c.passed,
                "reason_code": c.reason_code,
                "plain_explanation": c.plain_explanation,
            }
            for c in self.checks
        ]


@dataclass
class RequestContext:
    actor_id: str
    role: str
    unit: str
    clearance: int
    account_status: str
    device_id: str | None
    document_classification: int | None
    document_status: str | None
    document_unit_scope: list[str]
    document_role_scope: list[str]
    granted: bool
    device_status: str | None
    device_trust: str | None
    device_owner_id: str | None
    signing_key_status: str | None
    signing_key_expired: bool
    kem_key_status: str | None
    nonce_consumed: bool
    nonce_expired: bool
    nonce_owner_match: bool
    lockdown_active: bool
    document_expired: bool = False
    session_budget_exhausted: bool = False
    offline_requested: bool = False
    offline_allowed: bool = True
    offline_grant_expired: bool = False
    offline_grant_revoked: bool = False
    #: Declared trusted zone for this request (X-Sentinel-Zone), and the
    #: document's own zone restriction. Empty list = unrestricted.
    location_zone: str | None = None
    document_allowed_zones: list[str] = field(default_factory=list)
    decrypt_right: str = "ALLOW"
    break_glass_approved: bool = False
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def evaluate_decryption(
    context: RequestContext, *, device_policy: str = DeviceAccessPolicy.ALLOW
) -> Decision:
    """Zero-trust gate.

    Every check is re-evaluated from live state on each request. Nothing is
    cached and nothing is inherited from the login, so revoking a recipient, a
    device or a key takes effect on the very next call.
    """
    checks: list[Check] = []

    def record(name: str, passed: bool, reason: str, plain: str) -> None:
        checks.append(Check(name=name, passed=passed, reason_code=reason, plain_explanation=plain))

    record(
        "identity_valid",
        bool(context.actor_id) and context.role in Role.ALL,
        "IDENTITY_VALID" if context.actor_id and context.role in Role.ALL else "IDENTITY_UNKNOWN",
        "The request carried a recognised cryptographic identity.",
    )
    record(
        "account_active",
        context.account_status == AccountStatus.ACTIVE,
        "ACCOUNT_ACTIVE"
        if context.account_status == AccountStatus.ACTIVE
        else f"ACCOUNT_{context.account_status}",
        "The account is in good standing and has not been suspended or revoked.",
    )
    record(
        "need_to_know_grant",
        context.granted,
        "GRANT_PRESENT" if context.granted else "NEED_TO_KNOW_MISSING",
        "This recipient was individually authorised for this specific document.",
    )
    clearance_ok = (
        context.document_classification is not None
        and context.clearance >= context.document_classification
    )
    record(
        "clearance_sufficient",
        clearance_ok,
        "CLEARANCE_OK"
        if clearance_ok
        else f"CLEARANCE_BELOW_{_clearance_label(context.document_classification)}",
        "The recipient's clearance is at least as high as the document's classification.",
    )
    unit_ok = (not context.document_unit_scope) or ("*" in context.document_unit_scope) or (
        context.unit in context.document_unit_scope
    )
    record(
        "unit_need_to_know",
        unit_ok,
        "UNIT_SCOPE_OK" if unit_ok else "UNIT_OUT_OF_SCOPE",
        "The recipient's unit is inside the document's distribution scope.",
    )
    role_ok = (not context.document_role_scope) or (context.role in context.document_role_scope)
    record(
        "role_permitted",
        role_ok,
        "ROLE_PERMITTED" if role_ok else "ROLE_NOT_PERMITTED",
        "The document's policy permits this kind of identity to receive it.",
    )
    right_ok = context.decrypt_right == "ALLOW"
    record(
        "decrypt_right",
        right_ok,
        "DECRYPT_RIGHT_ALLOWED" if right_ok else "DECRYPT_RIGHT_DENIED",
        "The document's usage policy permits decryption of this document.",
    )

    device_ok, device_reason = _device_verdict(context, device_policy)
    record(
        "device_authorized",
        device_ok,
        device_reason,
        "Only a registered, trusted device belonging to this recipient may decrypt.",
    )
    record(
        "document_valid",
        context.document_status == DocumentAccess.SEALED and not context.document_expired,
        "DOCUMENT_SEALED"
        if context.document_status == DocumentAccess.SEALED and not context.document_expired
        else (
            "DOCUMENT_EXPIRED"
            if context.document_expired
            else f"DOCUMENT_{context.document_status}"
        ),
        "The document is sealed, unexpired, and has not been suspended or revoked.",
    )
    keys_ok = (
        context.signing_key_status in ("ACTIVE", "EXPIRING")
        and not context.signing_key_expired
        and context.kem_key_status in ("ACTIVE", "EXPIRING")
    )
    if not keys_ok:
        key_reason = (
            "KEY_EXPIRED"
            if context.signing_key_expired
            else f"KEY_{context.signing_key_status or 'MISSING'}"
        )
    else:
        key_reason = "KEYS_USABLE"
    record(
        "keys_valid",
        keys_ok,
        key_reason,
        "The recipient's post-quantum signing and key-establishment keys are usable.",
    )
    nonce_ok = not (context.nonce_consumed or context.nonce_expired or not context.nonce_owner_match)
    record(
        "session_valid",
        nonce_ok,
        "NONCE_FRESH" if nonce_ok else "NONCE_REPLAYED_OR_INVALID",
        "The request carries a single-use nonce that has not been seen before.",
    )
    record(
        "session_budget",
        not context.session_budget_exhausted,
        "SESSION_BUDGET_OK"
        if not context.session_budget_exhausted
        else "MAXIMUM_SESSIONS_REACHED",
        "The document's policy limit on decryption sessions has not been reached.",
    )
    if not context.offline_requested:
        offline_ok, offline_reason = True, "OFFLINE_OK"
        offline_plain = "The request did not ask for offline access."
    elif not context.offline_allowed:
        offline_ok, offline_reason = False, "OFFLINE_NOT_PERMITTED"
        offline_plain = "The document's policy allows this operation while the network is partitioned."
    elif context.offline_grant_revoked:
        offline_ok, offline_reason = False, "OFFLINE_GRANT_REVOKED"
        offline_plain = (
            "The offline access window for this device was revoked. One authenticated "
            "online session re-establishes a window; the withdrawal itself stays on record."
        )
    elif context.offline_grant_expired:
        offline_ok, offline_reason = False, "OFFLINE_GRANT_EXPIRED"
        offline_plain = (
            "The offline access window for this device has elapsed. One online "
            "session renews it before offline use can continue."
        )
    else:
        offline_ok, offline_reason = True, "OFFLINE_OK"
        offline_plain = "The document's policy allows this operation while the network is partitioned."
    record(
        "offline_permitted",
        offline_ok,
        offline_reason,
        offline_plain,
    )
    if not context.document_allowed_zones:
        location_ok, location_reason = True, "LOCATION_NOT_RESTRICTED"
        location_plain = "The document does not restrict decryption to particular trusted zones."
    elif context.location_zone is None:
        location_ok, location_reason = False, "LOCATION_UNKNOWN"
        location_plain = (
            "The document is restricted to trusted zones and this request declared no zone "
            "(X-Sentinel-Zone header)."
        )
    elif context.location_zone in context.document_allowed_zones:
        location_ok, location_reason = True, "LOCATION_OK"
        location_plain = (
            f"Request zone {context.location_zone} is inside the document's trusted zones."
        )
    else:
        location_ok, location_reason = False, "LOCATION_NOT_ALLOWED"
        location_plain = (
            f"Request zone {context.location_zone} is outside the document's trusted zones "
            f"({', '.join(context.document_allowed_zones)})."
        )
    record(
        "location_permitted",
        location_ok,
        location_reason,
        location_plain,
    )
    policy_ok = (not context.lockdown_active) or context.break_glass_approved
    record(
        "policy_allows",
        policy_ok,
        "POLICY_ALLOWS" if policy_ok else "EMERGENCY_LOCKDOWN_ACTIVE",
        "No emergency lockdown currently blocks this operation.",
    )

    failed = [c for c in checks if not c.passed]
    second_approval = bool(device_policy == DeviceAccessPolicy.REQUIRE_SECOND_APPROVAL and not failed)
    return Decision(
        allowed=not failed,
        reason_code=failed[0].reason_code if failed else "ACCESS_GRANTED",
        plain_explanation=failed[0].plain_explanation if failed else "All security checks passed.",
        checks=checks,
        requires_second_approval=second_approval,
    )


def _device_verdict(context: RequestContext, device_policy: str) -> tuple[bool, str]:
    """Reports precisely why a device was refused.

    A single catch-all code would tell an operator "device not authorised" when
    the real problem is that the device belongs to somebody else, which sends
    the investigation in the wrong direction.
    """
    if device_policy == DeviceAccessPolicy.DENY:
        return False, "DEVICE_POLICY_DENY"
    if not context.device_id or context.device_status is None:
        return False, "DEVICE_NOT_REGISTERED"
    if context.device_status != "ACTIVE":
        return False, "DEVICE_INACTIVE"
    if context.device_owner_id != context.actor_id:
        return False, "DEVICE_NOT_AUTHORIZED"
    if context.device_trust not in (None, "TRUSTED", "PENDING"):
        return False, f"DEVICE_{context.device_trust}"
    return True, "DEVICE_AUTHORIZED"


def _clearance_label(value: int | None) -> str:
    if value is None:
        return "UNKNOWN"
    try:
        return Clearance(value).label
    except ValueError:
        return "UNKNOWN"


def raise_for_decision(decision: Decision, *, recipient_status: str | None = None) -> None:
    """Maps a denial onto the specific error the operator needs to see.

    The revoked case is read from the decision itself when the caller does not
    restate it, so the same refusal cannot be reported as a generic denial just
    because a call site forgot to pass the status through.
    """
    revoked = recipient_status == AccountStatus.REVOKED or decision.reason_code == "ACCOUNT_REVOKED"
    if revoked:
        raise RecipientRevoked(
            "This recipient has been revoked.",
            detail="Revocation is immediate; historical records remain intact.",
        )
    if decision.reason_code.startswith("DEVICE_"):
        raise DeviceNotAuthorized(
            "The device used for this request is not a registered, trusted device of this recipient.",
            detail="Register the device or use the authorised endpoint.",
        )
    if decision.reason_code == "EMERGENCY_LOCKDOWN_ACTIVE":
        raise LockdownActive()
    if decision.requires_second_approval:
        raise ApprovalRequired(
            "This device policy requires a second authorised identity to approve the decryption."
        )
    if not decision.allowed:
        raise AuthorizationDenied(decision.plain_explanation, detail=decision.reason_code)
