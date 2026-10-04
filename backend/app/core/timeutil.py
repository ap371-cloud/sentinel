from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    """SQLite has no timezone storage, so values read back from a datetime
    column arrive naive. Comparing one of those directly with an aware value
    raises, which is why every time comparison in this project goes through
    here rather than open-coding a tzinfo replacement at each call site.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def iso(value: datetime | None) -> str | None:
    return as_utc(value).isoformat(timespec="seconds") if value is not None else None


def has_expired(value: datetime | None, *, reference: datetime | None = None) -> bool:
    if value is None:
        return False
    return as_utc(reference or utcnow()) > as_utc(value)


def has_passed_from(moment: datetime, value: datetime) -> bool:
    return as_utc(moment) > as_utc(value)
