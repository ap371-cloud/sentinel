"""Per-right usage policy — the granular-rights core.

A document's policy is not one "access granted" boolean: each usage right is
evaluated independently so an operator can allow DOWNLOAD while denying PRINT,
or keep VIEW open while key recovery stays a separate privileged act. The
effective decision for a right is layered:

    classification default  <  document's legacy boolean columns  <  explicit rights overrides

Classification defaults are the label's baseline (TOP_SECRET never downloads by
default); the boolean columns are the document-level decision recorded at
classification time; the rights override map is the per-document customisation
a document administrator sets after the fact.
"""

from __future__ import annotations

import json
from typing import Any

from .exceptions import AuthorizationDenied, ForgeError

ALLOW = "ALLOW"
DENY = "DENY"

RIGHTS: tuple[str, ...] = (
    "VIEW",
    "EDIT",
    "PRINT",
    "COPY",
    "DOWNLOAD",
    "EXPORT",
    "FORWARD",
    "SHARE",
    "SCREENSHOT",
    "OFFLINE",
    "DECRYPT",
    "RENDER",
    "RECOVER_KEY",
)

#: Rights whose document-level decision still lives in the legacy boolean
#: columns, kept for compatibility with existing rows, payloads and UI.
LEGACY_COLUMNS: dict[str, str] = {
    "DOWNLOAD": "download_allowed",
    "PRINT": "print_allowed",
    "EXPORT": "export_allowed",
    "OFFLINE": "offline_allowed",
}

SOURCE_EXPLICIT = "EXPLICIT_OVERRIDE"
SOURCE_DOCUMENT = "DOCUMENT_POLICY"
SOURCE_CLASSIFICATION = "CLASSIFICATION_DEFAULT"

_SOURCE_RANK = {SOURCE_CLASSIFICATION: 0, SOURCE_DOCUMENT: 1, SOURCE_EXPLICIT: 2}


def _baseline() -> dict[str, str]:
    matrix = {right: ALLOW for right in RIGHTS}
    matrix["RECOVER_KEY"] = DENY
    return matrix


def _restricted(extra: dict[str, str]) -> dict[str, str]:
    matrix = _baseline()
    matrix.update(extra)
    return matrix


#: Label → default matrix. The labels are the existing clearance scale
#: (UNCLASSIFIED ≈ public, RESTRICTED ≈ internal); renaming them would break
#: stored documents and every existing control that reads them.
_DEFAULTS: dict[str, dict[str, str]] = {
    "UNCLASSIFIED": _baseline(),
    "RESTRICTED": _restricted(
        {"EXPORT": DENY, "FORWARD": DENY, "SHARE": DENY}
    ),
    "CONFIDENTIAL": _restricted(
        {
            "EDIT": DENY,
            "PRINT": DENY,
            "COPY": DENY,
            "EXPORT": DENY,
            "FORWARD": DENY,
            "SHARE": DENY,
            "SCREENSHOT": DENY,
            "OFFLINE": DENY,
        }
    ),
    "SECRET": _restricted(
        {
            "EDIT": DENY,
            "PRINT": DENY,
            "COPY": DENY,
            "EXPORT": DENY,
            "FORWARD": DENY,
            "SHARE": DENY,
            "SCREENSHOT": DENY,
            "OFFLINE": DENY,
        }
    ),
    "TOP_SECRET": _restricted(
        {
            "EDIT": DENY,
            "PRINT": DENY,
            "COPY": DENY,
            "DOWNLOAD": DENY,
            "EXPORT": DENY,
            "FORWARD": DENY,
            "SHARE": DENY,
            "SCREENSHOT": DENY,
            "OFFLINE": DENY,
        }
    ),
}

#: An unknown label is treated as the strictest known policy rather than the
#: most permissive: corrupted classification data must fail closed.
_DEFAULT_UNKNOWN = _DEFAULTS["TOP_SECRET"]


def classification_defaults(classification: str) -> dict[str, str]:
    return dict(_DEFAULTS.get(classification, _DEFAULT_UNKNOWN))


def parse_overrides(raw: str | None) -> dict[str, str]:
    """Reads the per-document rights map, silently ignoring anything that is
    not a known right with a known verdict — invalid entries must not be able
    to widen access, and they were rejected at write time anyway."""
    try:
        raw_map = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    if not isinstance(raw_map, dict):
        return {}
    return {
        right: verdict
        for right, verdict in raw_map.items()
        if right in RIGHTS and verdict in (ALLOW, DENY)
    }


def validate_overrides(overrides: dict[str, Any]) -> dict[str, str]:
    """Write-time gate: unknown rights and unknown verdicts are rejected
    loudly instead of being dropped silently."""
    clean: dict[str, str] = {}
    for right, verdict in overrides.items():
        if right not in RIGHTS:
            raise ForgeError(
                f"{right} is not a recognised usage right.",
                detail=f"Known rights: {', '.join(RIGHTS)}",
            )
        if verdict not in (ALLOW, DENY):
            raise ForgeError(
                f"{right} must be ALLOW or DENY, not {verdict}.",
                detail="RIGHT_VALUE_INVALID",
            )
        clean[right] = verdict
    return clean


def right_sources(document: Any) -> dict[str, str]:
    layers: dict[str, list[tuple[int, str]]] = {
        right: [(_SOURCE_RANK[SOURCE_CLASSIFICATION], SOURCE_CLASSIFICATION)]
        for right in RIGHTS
    }
    for right, column in LEGACY_COLUMNS.items():
        value = getattr(document, column, None)
        if value is not None:
            layers[right].append((_SOURCE_RANK[SOURCE_DOCUMENT], SOURCE_DOCUMENT))
    for right in parse_overrides(getattr(document, "rights", None)):
        layers[right].append((_SOURCE_RANK[SOURCE_EXPLICIT], SOURCE_EXPLICIT))
    return {right: max(layers[right])[1] for right in RIGHTS}


def effective_rights(document: Any) -> dict[str, str]:
    rights = classification_defaults(getattr(document, "classification", None) or "")
    for right, column in LEGACY_COLUMNS.items():
        value = getattr(document, column, None)
        if value is not None:
            rights[right] = ALLOW if value else DENY
    rights.update(parse_overrides(getattr(document, "rights", None)))
    return rights


def evaluate_right(document: Any, right: str) -> tuple[bool, str, str]:
    """Returns (allowed, reason_code, plain_explanation) for one right."""
    if right not in RIGHTS:
        return False, f"RIGHT_{right}_UNKNOWN", f"{right} is not a usage right this system knows."
    verdict = effective_rights(document).get(right, DENY)
    source = right_sources(document)[right]
    allowed = verdict == ALLOW
    reason = f"RIGHT_{right}_{'ALLOWED' if allowed else 'DENIED'}"
    plain = (
        f"{right} is {'permitted' if allowed else 'denied'} for this document "
        f"(decided by {source.lower().replace('_', ' ')})."
    )
    return allowed, reason, plain


def require_right(document: Any, right: str, *, operation: str) -> None:
    allowed, reason, plain = evaluate_right(document, right)
    if not allowed:
        raise AuthorizationDenied(
            f"{operation} is denied by the document's usage policy.",
            detail=f"{reason}: {plain}",
        )


def policy_matrix(document: Any) -> dict[str, Any]:
    """The full explainable rights picture for API responses and UI."""
    return {
        "rights": effective_rights(document),
        "right_sources": right_sources(document),
        "rights_overrides": parse_overrides(getattr(document, "rights", None)),
        "classification_defaults": classification_defaults(
            getattr(document, "classification", None) or ""
        ),
    }
