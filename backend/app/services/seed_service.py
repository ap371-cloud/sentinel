"""Synthetic demo identities, devices and documents.

Nothing here references real personnel, units or operations. Every name, unit
and document is invented for demonstration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pymupdf
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import PATHS, Clearance, DeviceTrust, Role
from ..crypto.signatures import SERVER_IDENTITY, ensure_server_identity
from ..models.documents import Document
from ..models.identity import Device, Recipient
from . import approval_service, document_service, identity_service

UNITS = ("ALPHA", "BRAVO", "CHARLIE")

DEMO_USERS: tuple[dict[str, Any], ...] = (
    {
        "recipient_id": "COMMANDER-001",
        "display_name": "Synthetic Commander",
        "role": Role.COMMANDER,
        "unit": "ALPHA",
        "clearance": Clearance.TOP_SECRET.value,
        "password": "Commander!2026",
    },
    {
        "recipient_id": "SECURITY-001",
        "display_name": "Synthetic Security Officer",
        "role": Role.SECURITY_OFFICER,
        "unit": "ALPHA",
        "clearance": Clearance.TOP_SECRET.value,
        "password": "Security!2026",
    },
    {
        "recipient_id": "ADMIN-001",
        "display_name": "Synthetic Document Administrator",
        "role": Role.DOCUMENT_ADMIN,
        "unit": "BRAVO",
        "clearance": Clearance.SECRET.value,
        "password": "Admin!2026",
    },
    {
        "recipient_id": "RECIPIENT-001",
        "display_name": "Synthetic Recipient One",
        "role": Role.RECIPIENT,
        "unit": "BRAVO",
        "clearance": Clearance.CONFIDENTIAL.value,
        "password": "Recipient1!2026",
    },
    {
        "recipient_id": "RECIPIENT-002",
        "display_name": "Synthetic Recipient Two",
        "role": Role.RECIPIENT,
        "unit": "BRAVO",
        "clearance": Clearance.CONFIDENTIAL.value,
        "password": "Recipient2!2026",
    },
    {
        "recipient_id": "INVESTIGATOR-001",
        "display_name": "Synthetic Investigator",
        "role": Role.INVESTIGATOR,
        "unit": "CHARLIE",
        "clearance": Clearance.TOP_SECRET.value,
        "password": "Investigator!2026",
    },
    {
        "recipient_id": "AUDITOR-001",
        "display_name": "Synthetic Auditor",
        "role": Role.AUDITOR,
        "unit": "CHARLIE",
        "clearance": Clearance.SECRET.value,
        "password": "Auditor!2026",
    },
    {
        "recipient_id": "LEDGER-001",
        "display_name": "Synthetic Ledger Operator",
        "role": Role.LEDGER_OPERATOR,
        "unit": "BRAVO",
        "clearance": Clearance.CONFIDENTIAL.value,
        "password": "Ledger!2026",
    },
)

DEMO_DEVICES: tuple[tuple[str, str], ...] = (
    ("RECIPIENT-001", "DEV-RECIPIENT-001-A"),
    ("RECIPIENT-002", "DEV-RECIPIENT-002-A"),
    ("COMMANDER-001", "DEV-COMMANDER-001-A"),
    ("SECURITY-001", "DEV-SECURITY-001-A"),
    ("INVESTIGATOR-001", "DEV-INVESTIGATOR-001-A"),
    ("ADMIN-001", "DEV-ADMIN-001-A"),
)

DEMO_DOCUMENTS: tuple[dict[str, Any], ...] = (
    {
        "title": "SYNTHETIC SECURE BRIEF 001",
        "classification": Clearance.CONFIDENTIAL.name,
        "unit": "BRAVO",
        "mission_reference": "DEMO-MISSION-A",
        "recipients": ["RECIPIENT-001", "RECIPIENT-002"],
        "policy": {"export_allowed": True, "print_allowed": False, "offline_allowed": True},
    },
    {
        "title": "SYNTHETIC LOGISTICS REPORT 002",
        "classification": Clearance.RESTRICTED.name,
        "unit": "BRAVO",
        "mission_reference": "DEMO-MISSION-B",
        "recipients": ["RECIPIENT-001"],
        "policy": {"export_allowed": True, "offline_allowed": True},
    },
    {
        "title": "SYNTHETIC TECHNICAL REPORT 003",
        "classification": Clearance.SECRET.name,
        "unit": "ALPHA",
        "mission_reference": "DEMO-MISSION-C",
        "recipients": ["COMMANDER-001"],
        "policy": {"export_allowed": False, "second_approval_required": True, "offline_allowed": False},
    },
)

BODY_TEMPLATE = """{title}

CLASSIFICATION: {classification}
OWNING UNIT: {unit}
MISSION REFERENCE: {mission}

1. This is a synthetic demonstration document generated for a forensic
   attribution prototype. Every statement below is invented.

2. Element readiness is confirmed at 0600 and reported through the unit
   briefing chain. Two officers from each company attend.

3. Equipment draw is signed against the quartermaster record. Discrepancies
   are reported within the same period.

4. Any holder of this document who finds a copy outside the authorised
   distribution list should notify the security officer immediately.

5. This document is watermarked individually per decryption session so that
   a leaked copy can be traced to the session that produced it.

Section {n} of {sections} — routine demonstration content, no operational
information is present.
"""


def synthetic_document(title: str, classification: str, unit: str, mission: str, *, sections: int = 3) -> Path:
    destination = PATHS.render / f"source_{abs(hash(title)) % 10**8}.pdf"
    destination.parent.mkdir(parents=True, exist_ok=True)
    document = pymupdf.open()
    for page_index in range(2):
        page = document.new_page(width=595, height=842)
        body = BODY_TEMPLATE.format(
            title=title,
            classification=classification.replace("_", " "),
            unit=unit,
            mission=mission,
            n=page_index + 1,
            sections=sections,
        )
        page.insert_textbox(pymupdf.Rect(56, 56, 540, 790), body, fontsize=10.5)
    document.save(destination)
    document.close()
    return destination


def seed(session: Session, *, force: bool = False) -> dict[str, Any]:
    """Creates the synthetic environment. Safe to call repeatedly."""
    ensure_server_identity()
    approval_service.active_policy(session)

    created_users: list[str] = []
    for spec in DEMO_USERS:
        if session.get(Recipient, spec["recipient_id"]) is not None and not force:
            continue
        if force:
            session.query(Recipient).filter(Recipient.recipient_id == spec["recipient_id"]).delete()
            continue
        identity_service.create(
            session,
            recipient_id=spec["recipient_id"],
            display_name=spec["display_name"],
            role=spec["role"],
            unit=spec["unit"],
            clearance=spec["clearance"],
            password=spec["password"],
            actor_id="SYSTEM",
            email=f"{spec['recipient_id'].lower()}@demo.invalid",
        )
        created_users.append(spec["recipient_id"])

    created_devices: list[str] = []
    for recipient_id, device_id in DEMO_DEVICES:
        if session.get(Device, device_id) is not None and not force:
            continue
        if force:
            session.query(Device).filter(Device.device_id == device_id).delete()
            continue
        identity_service.register_device(
            session,
            recipient_id=recipient_id,
            device_id=device_id,
            device_name=f"{recipient_id} workstation",
            fingerprint=f"fp-{device_id.lower()}-demo",
            actor_id="SYSTEM",
        )
        device = session.get(Device, device_id)
        if device is not None:
            device.trust_state = DeviceTrust.TRUSTED
            device.trust_assessed_at = document_service._utcnow()
            device.trust_note = (
                "Marked TRUSTED by the seeding process. In production this state comes from hardware "
                "attestation, not from an administrator decision."
            )
        created_devices.append(device_id)

    created_documents: list[str] = []
    admin = session.get(Recipient, "ADMIN-001")
    for spec in DEMO_DOCUMENTS:
        if admin is None:
            break
        existing = session.execute(
            select(Document).where(Document.title == spec["title"])
        ).scalar_one_or_none()
        if existing is not None and not force:
            continue
        source = synthetic_document(
            spec["title"], spec["classification"], spec["unit"], spec["mission_reference"]
        )
        created = document_service.create_document(
            session,
            actor=admin,
            source=source,
            title=spec["title"],
            classification=spec["classification"],
            unit=spec["unit"],
            mission_reference=spec["mission_reference"],
            permitted_units=[spec["unit"]],
            permitted_roles=[Role.RECIPIENT, Role.COMMANDER, Role.SECURITY_OFFICER],
            recipient_ids=spec["recipients"],
            policy=spec["policy"],
        )
        created_documents.append(created["document_id"])

    return {
        "users_created": created_users,
        "devices_created": created_devices,
        "documents_created": created_documents,
        "units": list(UNITS),
        "demo_credentials": {
            spec["recipient_id"]: {"role": spec["role"], "password": spec["password"]}
            for spec in DEMO_USERS
        },
        "synthetic_data_notice": (
            "Every identity, unit and document in this environment is invented for demonstration. "
            "None of it describes real personnel, real units or real operations."
        ),
        "passwords_are_demo_only": True,
    }


def register_node_identities() -> list[str]:
    from ..crypto.key_management import VAULT

    known = {record["owner_id"] for record in VAULT.public_metadata()}
    return sorted({SERVER_IDENTITY, *known})


def devices_map(session: Session) -> dict[str, str]:
    return {
        device.recipient_id: device.device_id
        for device in session.execute(select(Device).where(Device.status == "ACTIVE")).scalars()
    }


def policy_snapshot(session: Session) -> dict[str, Any]:
    policy = approval_service.active_policy(session)
    return {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "name": policy.name,
        "device_access_policy": policy.device_access_policy,
        "replay_window_seconds": policy.replay_window_seconds,
        "break_glass_enabled": policy.break_glass_enabled,
        "high_risk_actions": json.loads(policy.high_risk_actions or "[]"),
        "updated_by": policy.updated_by,
        "updated_at": policy.updated_at.isoformat(timespec="seconds"),
    }
