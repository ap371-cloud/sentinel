from __future__ import annotations

import re

from ..core.exceptions import ForgeError

#: A trusted zone is a local identifier the deployment defines itself
#: (HQ-CAMPUS, FIELD-DEPLOYMENT, RECOVERY-VAULT, ...). Nothing here ever
#: calls an external geolocation service — the air-gap forbids it.
ZONE_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,63}$")
ZONE_HEADER = "x-sentinel-zone"
MAX_ZONES_PER_DOCUMENT = 8

LIMITATION = (
    "Zone enforcement runs on the X-Sentinel-Zone request header, a declared "
    "trusted-zone identifier set by the gateway or client. SENTINEL is "
    "air-gapped and never resolves a physical position; proven location "
    "assurance needs network-posture or attested-device signals and is "
    "APPLICATION DEPENDENT here."
)


def validate_zones(zones: object) -> list[str]:
    """Normalises the zone list a document policy declares."""
    if not isinstance(zones, list):
        raise ForgeError("allowed_locations must be a list of zone names.")
    if len(zones) > MAX_ZONES_PER_DOCUMENT:
        raise ForgeError(
            f"A document may be restricted to at most {MAX_ZONES_PER_DOCUMENT} trusted zones."
        )
    cleaned: list[str] = []
    for zone in zones:
        if not isinstance(zone, str) or not zone.strip():
            raise ForgeError("Each trusted zone must be a non-empty name.")
        name = zone.strip().upper()
        if not ZONE_PATTERN.match(name):
            raise ForgeError(
                f"Trusted zone {name!r} may only contain letters, digits, dots, dashes or underscores."
            )
        if name not in cleaned:
            cleaned.append(name)
    return cleaned


def resolve_zone(header_value: str | None) -> str | None:
    """Reads the declared zone off the request.

    Case and whitespace are normalised so HQ-campus and hq-campus are the
    same zone; anything else is passed through and simply will not match a
    restricted document's list.
    """
    if header_value is None or not header_value.strip():
        return None
    return header_value.strip().upper()
