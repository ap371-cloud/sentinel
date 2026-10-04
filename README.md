# SENTINEL

**Secure Command Document Intelligence & Forensic Attribution** — a working local prototype for
multi-recipient encrypted document distribution with session-specific forensic attribution.

> **Working local prototype with documented security and production limitations.**
> Not certified for classified information. Not "production ready". Not unhackable.

---

## The problem this solves

A sensitive document is encrypted once and distributed to several authorised recipients. Every one of
them can decrypt it, and every one of them ends up with **byte-identical plaintext**. If a copy later
appears outside the authorised circle, there is nothing in the copy that points at a recipient — and
the access logs that would help can be edited by a privileged administrator.

SENTINEL closes that gap: **each successful decryption produces a unique, invisible forensic
watermark**, bound cryptographically to that decryption session and signed by the recipient's own
post-quantum key, committed to a tamper-evident offline ledger. A leaked copy can then be traced back
to the session that produced it.

---

## The one claim this system makes

```
Cryptographically verifiable association between a recovered document and an
authorised decryption session, subject to endpoint, watermark robustness and
evidence-integrity limitations.
```

**What it does not claim:** that a named individual physically leaked the document. A compromised
endpoint can photograph, screenshot or transcribe displayed content. That limitation is stated in the
UI, in every forensic report and in `docs/SECURITY_MODEL.md`.

---

## What actually works

| Capability | Status | Evidence |
|---|---|---|
| ML-DSA-65 signatures | **Real** | `pqcrypto` 1.0.0, FIPS 204 |
| ML-KEM-768 key establishment | **Real** | `pqcrypto` 1.0.0, FIPS 203 |
| AES-256-GCM document encryption | **Real** | `cryptography` |
| Session-specific invisible watermark | **Real, measured** | 37.0 dB PSNR, 0.967 SSIM, recovered from 6/6 tested transformations |
| Blind watermark extraction | **Real** | Keyed correlation; the original document is *not* an input |
| Recipient non-repudiation | **Real** | Signature verified against the recipient's registered public key |
| Service key cannot forge attribution | **Real** | Demonstrated in the attack lab |
| 3-node offline ledger, quorum certificates | **Real** | Merkle inclusion proofs verified per transaction |
| Tamper detection | **Real** | Forged block hash detected on one node; other nodes reported as divergent |
| Offline queue + synchronisation | **Real** | Events queued below quorum, zero loss on reconnect |
| Replay protection | **Real** | Server-issued single-use nonces |
| Emergency lockdown + break-glass | **Real** | Blocks decryptions, requires two distinct approvers |
| Two-person control | **Real** | Requester can never approve; approvals single-use |
| Anomaly rules | **Real, deterministic** | Explainable thresholds, no ML |
| Local AI (Ollama) | **Optional** | Summarisation only; never a decision input |
| Key storage | **Development abstraction** | Encrypted local vault, not an HSM |
| Device trust | **Development abstraction** | Registered fingerprint, not hardware attestation |

Run `python scripts/demo_end_to_end.py` and `python scripts/api_smoke.py` to see every claim above
executed rather than asserted.

---

## Architecture at a glance

```
COMMAND TERMINAL (React, dark UI, 127.0.0.1)
        │
        ▼
   FASTAPI  ──►  POLICY ENGINE (RBAC + ABAC + need-to-know, 14 checks)
        │                     │
        │                     ▼
        │              ZERO-TRUST GATE (identity, device, grant, clearance,
        │                              unit, policy, keys, replay, lockdown)
        ▼                     │
   IDENTITY SERVICE            ▼
        │              DECRYPTION SESSION (single-use nonce)
        │                     │
        │                     ▼
        │              ML-KEM-768 unwrap  ──►  AES-256-GCM decrypt
        │                                          │
        │                                          ▼
        │                              WATERMARK ENGINE (keyed HMAC tag,
        │                              8x8 DCT spread spectrum, 512
        │                              carriers/bit, blind extraction)
        │                                          │
        ▼                                          ▼
   AUDIT CHAIN  ◄──── ML-DSA-65 SIGNED EVENT ◄────┘
   (append-only,          │
    hash-chained)         ▼
                   OFFLINE PERMISSIONED LEDGER
                   NODE-A │ NODE-B │ NODE-C
                   quorum certificates, Merkle proofs
                          │
                          ▼
                   FORENSIC ENGINE ──► EVIDENCE REPORT (hashed)
                          │
                          ▼
                   INCIDENT ENGINE ──► COMMAND DASHBOARD
```

---

## The critical workflow, end to end

```
authorised recipient + registered device
      ↓  14 authorisation checks from live state
policy granted
      ↓
unique decryption session          SES-00000001
      ↓
session-specific watermark tag    e16c35e1e79a1a0b  (HMAC, carries no identity)
      ↓  embedded into the page image
signed decryption event            ML-DSA-65, recipient's own key
      ↓
committed to 3-node ledger         quorum of 2, Merkle proof issued
      ↓
copy leaks and is submitted
      ↓
blind watermark extraction         carrier-to-noise 10.4, 0 bit errors
      ↓
session matched                    SES-00000001
      ↓
document version confirmed         VERSION-001
      ↓
signature verified                 against RECIPIENT-001's public key
      ↓
ledger + Merkle proof verified     block BLK-00000001
      ↓
VERIFIED ASSOCIATION ──► hashed evidence report
```

And when it breaks:

| Attack | What the system actually does |
|---|---|
| Replayed authorisation | `REPLAY ATTACK DETECTED`, request refused, security event raised |
| Unregistered device | `DEVICE NOT AUTHORIZED` |
| Revoked recipient | `ACCESS DENIED — IDENTITY REVOKED`, history preserved |
| Forged ledger block hash | `LEDGER INTEGRITY: TAMPER DETECTED`, node reported divergent |
| Service key forges attribution | `SIGNATURE INVALID` |
| Edited leaked copy | `DOCUMENT MODIFIED`, never accepted as a valid leak |
| Unmarked copy submitted | `WATERMARK NOT RECOVERED`, nobody is blamed |
| Single approver on two-person action | Refused, `428 TWO_PERSON_APPROVAL_REQUIRED` |

---

## Technology

**Backend** — Python 3.11+, FastAPI, SQLAlchemy 2, SQLite, Pydantic
**Crypto** — `pqcrypto` (ML-KEM-768, ML-DSA-65), `cryptography` (AES-256-GCM, HKDF, scrypt)
**Watermarking** — PyMuPDF, NumPy, Pillow; custom 8×8 DCT spread-spectrum embedder
**Ledger** — custom permissioned chain: hash-linked blocks, RFC-6962 Merkle proofs, quorum certificates
**Frontend** — React 18 + TypeScript + Vite, dark command interface, local assets only
**AI** — Ollama, optional, localhost only, summarisation only
**Tests** — pytest, 183 tests, no mocks of the properties under test

---

## Install and run

Windows, PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt

# 1. backend — creates schemas, brings the ledger online, seeds synthetic identities
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000

# 2. frontend — in a second terminal
cd frontend
npm install
npm run dev          # http://127.0.0.1:5173
```

Open `http://127.0.0.1:5173` and sign in as `COMMANDER-001` / `Commander!2026`.

API documentation: `http://127.0.0.1:8000/api/docs`

### Verification commands

```powershell
# full forensic chain, 21 steps
.\.venv\Scripts\python.exe scripts\demo_end_to_end.py

# the same chain over real HTTP against the real ASGI app
.\.venv\Scripts\python.exe scripts\api_smoke.py

# automated suite
cd backend
..\.venv\Scripts\python.exe -m pytest ..\tests

# watermark calibration: measured PSNR, SSIM and extraction signal
.\.venv\Scripts\python.exe scripts\calibrate_watermark.py
```

---

## Demo identities

All synthetic. None describes a real person, unit or operation.

| Identity | Role | Passphrase | Demonstrates |
|---|---|---|---|
| `COMMANDER-001` | COMMANDER | `Commander!2026` | Command dashboard, two-person approval, lockdown |
| `SECURITY-001` | SECURITY_OFFICER | `Security!2026` | Revocation, key compromise, incident handling |
| `ADMIN-001` | DOCUMENT_ADMIN | `Admin!2026` | Identity administration — and *no* evidence or ledger power |
| `RECIPIENT-001` | RECIPIENT | `Recipient1!2026` | Authorised decryption, own watermarked copy |
| `RECIPIENT-002` | RECIPIENT | `Recipient2!2026` | A different watermark from the same document |
| `INVESTIGATOR-001` | INVESTIGATOR | `Investigator!2026` | Leak analysis, evidence report |
| `AUDITOR-001` | AUDITOR | `Auditor!2026` | Read-only verification of everything |
| `LEDGER-001` | LEDGER_OPERATOR | `Ledger!2026` | Ledger verification and synchronisation |

---

## Documentation

| Document | Purpose |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, trust boundaries, data flow, diagrams |
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Zero trust, RBAC/ABAC, keys, signatures, honest limits |
| [docs/SECURITY_SIMPLE.md](docs/SECURITY_SIMPLE.md) | Every feature explained without cryptography |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat → control → detection → evidence → limitation |
| [docs/PRODUCTION_GAPS.md](docs/PRODUCTION_GAPS.md) | What a real deployment must add |
| [docs/PROTOTYPE_VS_PRODUCTION.md](docs/PROTOTYPE_VS_PRODUCTION.md) | Side-by-side comparison |
| [docs/PQC.md](docs/PQC.md) | ML-KEM/ML-DSA, why AES is still used for content |
| [docs/WATERMARKING.md](docs/WATERMARKING.md) | Derivation, embedding, extraction, measured robustness |
| [docs/LEDGER.md](docs/LEDGER.md) | Blocks, Merkle proofs, quorum, tamper and offline behaviour |
| [docs/FORENSIC_PROCESS.md](docs/FORENSIC_PROCESS.md) | The evidence chain link by link |
| [docs/COMMANDER_GUIDE.md](docs/COMMANDER_GUIDE.md) | The whole system for a non-technical reader |
| [docs/SETUP.md](docs/SETUP.md) | Installation, configuration, troubleshooting |
| [docs/DEMO.md](docs/DEMO.md) | How to present the demonstration |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Every limitation in one place |

---

## Repository layout

```
backend/app/
  api/         FastAPI routers and dependency guards
  core/        configuration, policy engine, crypto primitives, egress guard
  crypto/      PQC provider, key vault, canonical signing
  documents/   PDF rendering, authenticated encryption, versioning
  watermark/   derivation, error correction, embedding, extraction, verdicts
  ledger/      Merkle tree, blocks, node replicas, quorum, verification
  forensic/    analysis, evidence, reports
  security/    incident engine, anomaly rules, lockdown, revocation, attack lab
  services/    identity, document, decryption, watermark, forensic, command, AI
  models/      relational schema
frontend/src/  React command interface
tests/         183 pytest cases
scripts/       demo, API smoke, smoke test, watermark calibration
data/ keys/ ledger/ evidence/   runtime state (regenerable, never committed)
```
