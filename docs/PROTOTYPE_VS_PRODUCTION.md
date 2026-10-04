# Prototype versus production

## Summary

This repository is a **working local prototype**. It implements the full forensic chain honestly and
demonstrates that the chain works. It is not a deployable product and carries no accreditation.

The difference is not a longer feature list. It is hardware, process and proof.

---

## Side by side

| Area | This prototype | A real deployment |
|---|---|---|
| **Post-quantum crypto** | ML-KEM-768, ML-DSA-65 via `pqcrypto` (compiled PQClean) | Validated module, Known Answer Test evidence, change control, approved provider list |
| **Key storage** | JSON file, keys encrypted under a scrypt-derived KEK | HSM or TPM, non-exportable keys, dual-control ceremonies, split root custody |
| **Device identity** | Client-asserted fingerprint, labelled as not attestation | TPM or Secure-Enclave attestation with revocation |
| **Authentication** | PBKDF2-HMAC-SHA256, local accounts | Argon2id, phishing-resistant MFA, enterprise identity provider |
| **Data at rest** | SQLite with WAL, local volumes | Hardened database engine, encrypted volumes, separate credentials per function |
| **Ledger** | 3 nodes as threads over separate files on one host | Independent processes or hosts, formally reviewed consensus |
| **Watermark** | Mid-frequency DCT, 512 carriers/bit, 37 dB PSNR | Independently evaluated robustness, collusion-resistant coding, target-hardware validation |
| **Endpoint** | Watermarked PDF written to a directory | Hardened endpoint, controlled viewer, capture controls, secure boot |
| **Operations** | No runbooks, no on-call, no DR drill | Incident response, recovery drills, retention policy, training |
| **Assurance** | Own test suite | Independent audit, penetration test, red team, model checking |
| **Legal** | Technically sound chain of custody | Jurisdictional compliance, expert standards, legal review |
| **Classification** | Application strings | Accreditation under an official scheme |

---

## What is genuinely implemented

These are not stubs. Each runs on every decryption and is covered by tests that use the real primitive.

- Session-specific invisible watermark with keyed derivation, mid-frequency spread-spectrum embedding,
  repetition redundancy, blind keyed extraction, measured carrier-to-noise confidence and honest
  `FOUND` / `WEAK MATCH` / `CORRUPTED` / `NOT FOUND` outcomes.
- Real ML-DSA-65 signatures by the recipient's own key, with the watermark tag inside the signed
  payload, domain-separated contexts, and canonical serialisation.
- Real ML-KEM-768 key establishment wrapping a per-recipient copy of the AES content key.
- AES-256-GCM document encryption with the document identity, version and content hash bound as
  associated data.
- Fourteen-check zero-trust authorisation with reason codes, evaluated from live state per request.
- Separation of duties enforced structurally, including a read-only role refused before any handler runs.
- Two-person control where the requester cannot approve and approvals are single-use.
- Emergency lockdown with two-person release, and auditable break-glass access.
- Three-node ledger with post-quantum quorum certificates, RFC-6962 Merkle proofs, independent
  recomputation, cross-node state roots, and scoped storage immutability triggers.
- Offline queueing and synchronisation with conflict recording and no silent overwrite.
- Forensic engine that verifies each chain link independently and names the failing one.
- Hashed, tamper-evident evidence reports with an explicit limitations block.
- Deterministic anomaly rules, an incident engine with recommended responses, and a hash-chained
  privileged-action audit log.
- Runtime egress enforcement that blocks every non-loopback socket.
- Optional local AI that is advisory only and whose absence changes nothing.

## What is a labelled abstraction

Clearly marked in code and in the interface. Not pretended to be stronger than it is.

| Component | Label | What it actually is |
|---|---|---|
| Key vault | `DEVELOPMENT KEYSTORE` | AES-256-GCM under a scrypt-derived KEK from a local file |
| Device trust | `SIMULATED DEVICE IDENTITY` | A fingerprint the client asserts |
| Ledger independence | `LOCAL 3-NODE LEDGER` | Separate database files, one host |
| Consensus | documented as such | Deterministic rotation, correct for 3 nodes, not a reviewed BFT protocol |
| Classification labels | `PROTOTYPE APPLICATION LABELS` | Strings, not an official scheme |
| Posture score | `PROTOTIVE OPERATIONAL INDICATOR` | A weighted mean of measured conditions |
| Ollama | `AI-ASSISTED ANALYSIS` | Summarisation, never a decision |

## What is not implemented at all

- Hardware key protection or attestation
- Endpoint hardening or capture controls
- Public or independent ledger verifiability
- Formal consensus safety argument
- Rate limiting, quotas or resource isolation
- Independent audit, penetration test or red team
- Incident response process, on-call or DR drill
- Multi-host deployment or genuine trust separation
- Legal or evidentiary compliance

---

## Honest scaling position

The prototype is sized for a demonstration: a handful of documents, a handful of recipients, a few
hundred sessions, three ledger nodes on one machine.

Per-operation cost on the development machine:

| Operation | Typical cost |
|---|---|
| ML-DSA-65 signature | ~6 ms |
| ML-DSA-65 verification | well under 1 ms |
| ML-KEM-768 keygen | ~1 ms |
| ML-KEM-768 encapsulate / decapsulate | ~1 ms |
| Watermark embed, 2 pages | ~2 s |
| Watermark blind extraction | ~3 s |
| Full ledger verification | ~0.2 s |

**Watermarking is the dominant cost** and it grows linearly with page count. A 200-page document would
take roughly two minutes to watermark, which is not acceptable for a real workflow.

If this were to be scaled, the changes would be: page-parallel embedding with a worker pool, extraction
restricted to a shortlist of candidate versions rather than all of them, ledger blocks carrying many
transactions instead of one, and moving the document service to object storage. None of that changes the
security model; all of it is engineering throughput.

---

## What would have to be true before deployment

1. Keys in hardware, non-exportable, with dual-control ceremonies.
2. Device identity attested by the platform, not asserted by the client.
3. Cryptographic module validated, with Known Answer Test evidence.
4. Endpoint hardening and a controlled viewer, with the rasterisation trade-off resolved.
5. Ledger replicas genuinely independent, with a reviewed consensus argument.
6. Watermark robustness independently evaluated against the real threat model, on real hardware.
7. Formal verification of the authorisation engine against intended policy.
8. Independent security audit and penetration test.
9. Incident response runbooks, recovery drills and retention policy in place.
10. Legal review of the forensic reporting process.
11. Accreditation under an official classification scheme.
12. Classification labels replaced by an authoritative scheme.

Items 1, 4 and 11 are the ones that cannot be worked around technically. Until they are addressed, the
system is a demonstration of a credible design — not a system that should be trusted with real material.
