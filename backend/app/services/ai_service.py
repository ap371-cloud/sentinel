"""Optional local intelligence layer (Ollama).

Hard boundary: this module may summarise, explain and cluster information that
the deterministic systems have already verified. It never participates in an
authorisation, signature, ledger or forensic decision, and its output is always
labelled as AI-assisted. If Ollama is absent the platform is unaffected.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from ..core.config import SETTINGS

AI_LABEL = "AI-ASSISTED ANALYSIS"
OFFLINE_LABEL = "AI SERVICE OFFLINE"

PROMPT_PREFIX = (
    "You are summarising verified security telemetry for a command dashboard. "
    "You do not make security decisions and you do not authorise anything. "
    "Answer in at most 120 words, in plain language, with no speculation. "
)


def _request(path: str, payload: dict[str, Any] | None = None, *, method: str = "GET") -> dict[str, Any]:
    url = f"{SETTINGS.ollama_url.rstrip('/')}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=SETTINGS.ollama_timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def health() -> dict[str, Any]:
    """Never raises. A missing or slow service is reported, not propagated."""
    try:
        response = _request("/api/tags")
        models = [entry.get("name", "") for entry in response.get("models", [])]
        wanted = SETTINGS.ollama_model
        return {
            "available": True,
            "endpoint": SETTINGS.ollama_url,
            "models": models,
            "configured_model": wanted,
            "model_present": any(m.split(":")[0] == wanted.split(":")[0] for m in models),
            "status": "ONLINE",
            "role": "Summarisation only. Never used for authorisation, verification or verdicts.",
        }
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return {
            "available": False,
            "endpoint": SETTINGS.ollama_url,
            "models": [],
            "configured_model": SETTINGS.ollama_model,
            "model_present": False,
            "status": OFFLINE_LABEL,
            "reason": type(exc).__name__,
            "role": "Summarisation only. Never used for authorisation, verification or verdicts.",
            "impact": "All deterministic security functions continue to operate normally.",
        }


def _offline(reason: str, request_summary: str) -> dict[str, Any]:
    return {
        "label": OFFLINE_LABEL,
        "available": False,
        "summary": None,
        "fallback": (
            "The local intelligence service is not reachable, so no narrative summary was produced. "
            "Every verification result shown on screen comes from deterministic checks and is "
            "unaffected."
        ),
        "requested": request_summary,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _complete(prompt: str, request_summary: str) -> dict[str, Any]:
    try:
        response = _request(
            "/api/generate",
            {
                "model": SETTINGS.ollama_model,
                "prompt": PROMPT_PREFIX + prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 220},
            },
            method="POST",
        )
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        offline = _offline(f"{type(exc).__name__}: {exc}", request_summary)
        offline["health"] = health()
        return offline
    return {
        "label": AI_LABEL,
        "available": True,
        "summary": (response.get("response") or "").strip(),
        "model": SETTINGS.ollama_model,
        "requested": request_summary,
        "authority": (
            "Advisory only. No authorisation, signature, ledger or forensic decision derives from this "
            "text."
        ),
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def summarise_incident(incident: dict[str, Any]) -> dict[str, Any]:
    """Explains an already-detected incident. Detection itself is deterministic."""
    facts = {
        "severity": incident.get("severity"),
        "title": incident.get("title"),
        "what_happened": incident.get("what_happened"),
        "why_it_matters": incident.get("why_it_matters"),
        "affected": incident.get("what_was_affected"),
        "recommended_action": incident.get("recommended_action"),
    }
    return _complete(
        "Here is a verified security incident as JSON. Explain it to a commander in plain language "
        "and state what decision is being requested of a human:\n"
        + json.dumps(facts, indent=1),
        f"incident:{incident.get('security_event_id') or incident.get('incident_id')}",
    )


def summarise_anomaly(observation: dict[str, Any]) -> dict[str, Any]:
    """Explains which deterministic rule fired and on what evidence."""
    facts = {
        "rule": observation.get("rule"),
        "observed_value": observation.get("observed_value"),
        "threshold": observation.get("threshold"),
        "triggered": observation.get("triggered"),
        "explanation": observation.get("explanation"),
        "subject": observation.get("subject_id"),
    }
    return _complete(
        "Here is a deterministic anomaly rule result as JSON. Explain why it looks unusual, in "
        "plain language, without recommending any action a system should take automatically:\n"
        + json.dumps(facts, indent=1),
        f"anomaly:{observation.get('rule')}:{observation.get('subject_id')}",
    )


def summarise_investigation(report: dict[str, Any]) -> dict[str, Any]:
    """Briefs an investigator on a forensic report the system has already verified."""
    facts = {
        "final_result": report.get("final_result", {}).get("status"),
        "recipient_association": report.get("association", {}).get("recipient_id"),
        "session_id": report.get("association", {}).get("session_id"),
        "document": report.get("document", {}).get("document_id"),
        "version": report.get("document", {}).get("version_number"),
        "watermark_verdict": report.get("watermark", {}).get("verdict"),
        "signature_verified": report.get("signed_event", {}).get("signature_verified"),
        "merkle_proof_verified": report.get("ledger", {}).get("merkle_proof_verified"),
        "limitations": report.get("limitations", [])[:3],
    }
    return _complete(
        "Here is a verified forensic report summary as JSON. Write a short briefing for the "
        "investigating officer, and state explicitly what the result does not prove:\n"
        + json.dumps(facts, indent=1),
        f"investigation:{report.get('case', {}).get('case_id')}",
    )


def commander_briefing(dashboard: dict[str, Any]) -> dict[str, Any]:
    """Turns measured dashboard state into a short narrative."""
    facts = {
        "system_status": dashboard.get("system_security_status"),
        "posture": dashboard.get("security_posture", {}).get("score"),
        "rating": dashboard.get("security_posture", {}).get("rating"),
        "kpis": dashboard.get("kpis"),
        "ledger": dashboard.get("ledger_health", {}).get("headline"),
        "top_events": [
            {
                "severity": event.get("severity"),
                "title": event.get("title"),
                "explanation": event.get("plain_explanation"),
            }
            for event in dashboard.get("live_security_events", [])[:6]
        ],
    }
    return _complete(
        "Here is measured command dashboard state as JSON. Write a short briefing: what is secure, "
        "what needs attention, and what a human must decide. Do not invent facts:\n"
        + json.dumps(facts, indent=1),
        "commander_briefing",
    )


def cluster_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Groups related events by category for triage."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        grouped.setdefault(event.get("category", "UNCLASSIFIED"), []).append(
            {
                "id": event.get("security_event_id"),
                "severity": event.get("severity"),
                "title": event.get("title"),
                "at": event.get("detected_at"),
            }
        )
    return {
        "label": "DETERMINISTIC GROUPING",
        "available": True,
        "clusters": [
            {"category": category, "count": len(items), "events": items}
            for category, items in sorted(grouped.items(), key=lambda item: -len(item[1]))
        ],
        "note": (
            "Grouping is computed locally by category. The language model is offered an optional "
            "narrative over these clusters but cannot change their membership."
        ),
    }
