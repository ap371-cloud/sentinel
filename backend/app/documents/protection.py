from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pymupdf as fitz

from ..core.config import SETTINGS
from ..database import shared as shared_store

RECEIPT_FILE = "sentinel-policy-receipt.json"

#: Honest statement of what a copy that leaves the controlled viewer does and
#: does not still enforce. Attached to every decrypted artefact and shown by
#: the API, because claiming kernel-level control over a file on someone
#: else's machine would be a fake security promise.
LIMITATION = (
    "POLICY ENFORCEMENT LIMITATION: once this copy leaves the controlled viewer, usage "
    "restrictions travel with the file as labels, metadata and an embedded policy receipt "
    "rather than as kernel-level enforcement. Attribution, signed audit evidence and "
    "revocation of any further access still apply; blocking every screenshot or onward "
    "copy on an unmanaged endpoint is APPLICATION DEPENDENT and is not claimed here."
)


def build_receipt(
    *,
    document: Any,
    version: Any,
    recipient_id: str,
    device_id: str,
    session_id: str,
    watermark_tag: str,
    event: Any,
    rights_matrix: dict[str, str],
    now: datetime | None = None,
) -> dict[str, Any]:
    moment = now or datetime.now(timezone.utc)
    return {
        "receipt_version": 1,
        "issued_at": moment.isoformat(timespec="seconds"),
        "document_id": document.document_id,
        "document_title": document.title,
        "version_id": version.version_id,
        "version_number": version.version_number,
        "document_sha256": version.content_sha256,
        "classification": document.classification,
        "recipient_id": recipient_id,
        "device_id": device_id,
        "session_id": session_id,
        "watermark_tag": watermark_tag,
        "event_id": event.event_id,
        "event_hash": event.event_hash,
        "ledger_tx_id": event.ledger_tx_id,
        "policy_version": document.policy_version,
        "rights": dict(sorted(rights_matrix.items())),
        "access_expiry": (
            document.access_expiry.isoformat(timespec="seconds") if document.access_expiry else None
        ),
        "offline": {
            "allowed": rights_matrix.get("OFFLINE") == "ALLOW",
            "max_hours": document.offline_max_hours,
        },
        "visible_watermark": {
            "enabled": document.visible_watermark,
            "template": SETTINGS.visible_watermark_template,
        },
        "notice": LIMITATION,
    }


def attach(output_path: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    """Writes the receipt into the artefact itself: an attached JSON file plus
    document-info stamps. An examiner opening the PDF months later can see
    under which policy, session and rights the copy was produced without
    asking this server."""
    payload = json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8")
    with fitz.open(output_path) as document:
        if RECEIPT_FILE in document.embfile_names():
            document.embfile_del(RECEIPT_FILE)
        document.embfile_add(
            RECEIPT_FILE,
            payload,
            filename=RECEIPT_FILE,
            ufilename=RECEIPT_FILE,
            desc="SENTINEL policy receipt for this decryption copy",
        )
        metadata = dict(document.metadata or {})
        metadata.update(
            {
                "creator": "SENTINEL",
                "subject": (
                    f"{receipt.get('classification', 'UNCLASSIFIED')} - SENTINEL protected copy "
                    f"for {receipt.get('recipient_id', 'unknown')} "
                    f"(session {receipt.get('session_id', 'unknown')})"
                ),
                "keywords": (
                    f"SENTINEL; CLASSIFICATION={receipt.get('classification', 'UNCLASSIFIED')}; "
                    f"POLICY={receipt.get('policy_version', 'unknown')}; "
                    f"SESSION={receipt.get('session_id', 'unknown')}; "
                    f"RECIPIENT={receipt.get('recipient_id', 'unknown')}"
                ),
            }
        )
        document.set_metadata(metadata)
        staging = output_path.with_name(f".{output_path.name}.policy-tmp")
        document.save(staging, garbage=3, deflate=True)
    staging.replace(output_path)
    shared_store.artefact_put_file(output_path)
    return summary(receipt)


def summary(receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "receipt_embedded": receipt is not None,
        "receipt_file": RECEIPT_FILE,
        "travels_with_file": [
            "embedded policy receipt (JSON)",
            "classification and session stamps in document info",
            "invisible forensic watermark",
            "visible deterrent text where enabled",
        ],
        "limitation": LIMITATION,
    }
    if receipt is not None:
        out["policy_version"] = receipt.get("policy_version")
        out["session_id"] = receipt.get("session_id")
    return out
