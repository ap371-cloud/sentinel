from __future__ import annotations


class ForgeError(Exception):
    """Base class so the API layer can map failures onto one JSON shape."""

    status = 400
    code = "FORGE_ERROR"
    plain_explanation = "The request could not be completed."

    def __init__(self, message: str | None = None, *, detail: str | None = None):
        self.message = message or self.plain_explanation
        self.detail = detail
        super().__init__(self.message)


class AuthenticationError(ForgeError):
    status = 401
    code = "AUTHENTICATION_FAILED"
    plain_explanation = "The identity could not be verified."


class AuthorizationDenied(ForgeError):
    status = 403
    code = "ACCESS_DENIED"
    plain_explanation = "This identity is not authorized for the requested action."


class RecipientRevoked(AuthorizationDenied):
    code = "RECIPIENT_REVOKED"
    plain_explanation = "This recipient has been revoked and cannot decrypt."


class DeviceNotAuthorized(AuthorizationDenied):
    code = "DEVICE_NOT_AUTHORIZED"
    plain_explanation = "This device is not registered to the recipient."


class ReplayDetected(AuthorizationDenied):
    code = "REPLAY_ATTACK_DETECTED"
    plain_explanation = "This request or session has already been used."


class LockdownActive(ForgeError):
    status = 423
    code = "EMERGENCY_LOCKDOWN_ACTIVE"
    plain_explanation = (
        "New sensitive operations are blocked while existing evidence remains preserved."
    )


class ApprovalRequired(ForgeError):
    status = 428
    code = "TWO_PERSON_APPROVAL_REQUIRED"
    plain_explanation = "A second authorized identity must approve before this can continue."


class TwoPersonControlViolation(ForgeError):
    status = 403
    code = "TWO_PERSON_CONTROL_VIOLATION"
    plain_explanation = "Requester and approver must be different identities."


class DocumentHashMismatch(ForgeError):
    status = 409
    code = "DOCUMENT_HASH_MISMATCH"
    plain_explanation = "The document content does not match the recorded version."


class WatermarkNotFound(ForgeError):
    status = 404
    code = "WATERMARK_NOT_FOUND"
    plain_explanation = "No forensic watermark could be recovered from this copy."


class SignatureInvalid(ForgeError):
    status = 409
    code = "SIGNATURE_INVALID"
    plain_explanation = "The cryptographic signature did not verify."


class LedgerTamperDetected(ForgeError):
    status = 409
    code = "LEDGER_TAMPER_DETECTED"
    plain_explanation = "Ledger integrity verification failed."


class OfflinePolicyViolation(ForgeError):
    status = 403
    code = "OFFLINE_SECURITY_POLICY_VIOLATION"
    plain_explanation = "Unexpected network activity or configuration was detected."


class NotFound(ForgeError):
    status = 404
    code = "NOT_FOUND"
    plain_explanation = "The requested record does not exist."
