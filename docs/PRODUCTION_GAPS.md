# Production gaps

This prototype is **not** production ready and is **not** certified for classified information. This
document lists, without hedging, what a real deployment must add.

---

## 1. Cryptographic validation

| Prototype | Production requirement |
|---|---|
| Uses `pqcrypto` 1.0.0, a compiled PQClean implementation behind a liboqs-compatible API | Algorithm implementations validated against official NIST Known Answer Test vectors, under change control |
| No FIPS validation boundary | Validated cryptographic module (FIPS 140-3 Level 2 or 3) for any deployment handling protected material |
| Provider interface with one backend | Approved provider list, pinning, and a documented migration path if a backend is withdrawn |
| Domain separation contexts chosen by the designers | Contexts and message formats formally specified and reviewed |

None of this means the code is wrong. It means nobody has *proved* it correct under a process a
certifying authority would accept.

## 2. Key protection

| Prototype | Production requirement |
|---|---|
| Private keys encrypted at rest under a scrypt-derived key derived from a local file or an environment passphrase | HSM or TPM-backed, non-exportable keys. The service should be unable to read a private key even with full memory access |
| Key vault is a JSON file | Hardware-backed keystore with audited key generation, import and ceremony procedures |
| Rotation is a metadata operation | Governed rotation with overlap windows, revocation propagation and rollback procedures |
| One shared root secret for watermark derivation | Split root management with independent custodians, or per-document derivation keys held in hardware |
| Revocation is immediate in-process | Revocation propagated across all nodes and all replicas within a defined time bound |

The single most consequential gap in this list is item 3 in the left column: **one root secret protects
every watermark derivation.** If it leaks, watermarks for the entire deployment can be forged.

## 3. Identity and authentication

| Prototype | Production requirement |
|---|---|
| Local PBKDF2-HMAC-SHA256 at 240k iterations | Argon2id or scrypt as the primary password KDF, plus mandatory second factor for sensitive roles |
| Synthetic local accounts | Enterprise identity provider with phishing-resistant MFA for approvers and administrators |
| Tokens in memory, 8 hour lifetime | Short-lived tokens, refresh rotation, session revocation, device-bound tokens |
| Lockout after five failures | Risk-based throttling with alerting rather than a fixed counter |
| No account lifecycle governance | Joiner-mover-leaver process, periodic access review, dormant account handling |

## 4. Device trust

| Prototype | Production requirement |
|---|---|
| Device fingerprint asserted by the client | TPM or Secure-Enclave backed device identity with attestation |
| Trust state set by an operator | Attestation-verified trust with revocation and re-attestation |
| Single registered device per identity | Device posture, patch level and EDR integration as policy inputs |
| Documented as not being attestation | Must be replaced before the control is claimed to be hardware-backed |

**As written, a determined attacker can present a stolen device identifier.** This is the clearest
example in the project of a labelled limitation rather than an implemented control.

## 5. Endpoint and platform security

| Prototype | Production requirement |
|---|---|
| Watermarked PDF written to a directory | Hardened endpoint with controlled viewer, full-disk encryption, secure boot |
| Text becomes rasterised during watermarking | Decision needed: either accept rasterisation, or use a controlled viewer with overlay watermarking |
| No screen-capture control | OS-level capture restriction where technically available, plus procedural controls |
| Python process holds keys in memory | Memory protection, key usage isolation, no core dumps |
| Runs on a developer operating system | Supported, hardened OS with a defined patch baseline |
| No code signing | Signed builds with verified provenance and a secure update path |

The endpoint gap cannot be closed by this codebase. It is the reason the system reports association
rather than responsibility.

## 6. Network and deployment

| Prototype | Production requirement |
|---|---|
| All components on one machine | Separated trust zones with a reviewed network architecture |
| Runtime egress guard blocking non-loopback sockets | Physical network isolation plus policy enforcement, verified independently of the application |
| SQLite with WAL | Hardened database engine, encrypted volumes, separate credentials per function |
| One process serving API and workers | Separation of duties at the deployment level, not only in the role model |
| Ledger nodes are threads over separate files | Independent processes or hosts so a node compromise is contained |

The egress guard is genuine enforcement and useful evidence of intent, but it is enforced *by the
process it protects*. Isolation must not depend on that.

## 7. Ledger and audit

| Prototype | Production requirement |
|---|---|
| Deterministic proposer rotation | Documented consensus with formal safety argument for the deployed node count |
| Quorum of 2 of 3 | Reviewed threshold; analysis of the Byzantine case |
| Local SQLite per node | Tamper-evident storage, possibly HSM-backed timestamps |
| Separate database files on one host | Genuinely independent replicas so independence is not assumed |
| No key destruction or archival | Key lifecycle for long-term verification, including algorithm agility |
| Audit chain anchored periodically | Continuous anchoring with independent timestamping |

## 8. Watermark robustness

| Prototype | Production requirement |
|---|---|
| 37.0 dB PSNR, 0.967 SSIM, recovered from 6 transformations | Independent robustness evaluation against the full threat model of the intended deployment |
| Mid-frequency DCT spread spectrum | Consider collusion-resistant coding, and evaluate against print/scan and camera capture on the actual target hardware |
| Text rasterised during embedding | Assessment of whether rasterisation is acceptable, or a controlled viewer instead |
| No collusion resistance | Research-grade collusion-resistant watermarking if the threat model includes colluding recipients |
| 64-bit tag | Review of tag length against the deployment's guessing-resistance requirement |
| Extraction searches five scale factors | Characterisation of real capture pipelines, including print/scan and phone photography |

**Not tested here, and not claimed:** angled photography, heavy cropping, print/scan on real hardware,
image model regeneration, and collusion. The system reports `NOT FOUND` in those cases rather than
guessing, which is the correct behaviour, but it is not a security guarantee.

## 9. Operational processes

None of the following is implemented, and all are required:

- Incident response runbooks and on-call procedures
- Forensic reporting standards and legal review of output
- Classification authority and scheme accreditation — the labels here are application strings
- Audit of the cryptographic provider and supply chain
- Vulnerability management and independent penetration testing
- Disaster recovery with tested restore procedures, including offline protected media
- Key ceremony documentation with dual control
- Retention and evidence-preservation policy
- Training for operators and investigators
- Change control with independent review

## 10. Assurance activities

| Not done | Required |
|---|---|
| Independent security audit | Full penetration test by an accredited team |
| Formal verification of the policy engine | Model checking of the authorisation rules against the intended policy |
| Fuzzing of parsers and PDF handling | Fuzzing of every input parser, especially PDF |
| Load and abuse testing | Capacity planning for the intended deployment scale |
| Red-team exercise | Adversary simulation against the complete system |

## 11. Known prototype-only behaviours

Honest inventory of things that are shortcuts:

1. **Single machine.** Nodes, API, ledger and key vault share a host. Independence is by file, not by
   trust boundary.
2. **Development key store.** See item 2.
3. **Simulated device trust.** See item 4.
4. **Consensus is deterministic rotation, not a reviewed BFT protocol.** It behaves correctly for this
   node count and is documented as such.
5. **Watermark robustness is measured on synthetic text documents.** Real scanned or mixed-media
   documents will behave differently.
6. **No rate limiting.** An authorised user can generate unbounded sessions.
7. **`evidence/` on local disk.** Real custody requires controlled, access-logged media.
8. **No formal incident response integration.** Security events exist; nobody is paged.
9. **Recovery is untested.** Backups are created and verified, but a full disaster-recovery drill has
   not been performed.
10. **The local AI path is optional and advisory.** It has not been evaluated for information leakage
    in a classified context.

---

## Honest summary

What this prototype demonstrates: the cryptographic and architectural chain works end to end, honestly
reports its own failures, and does not depend on trusting any single privileged account.

What it is not: a deployable product. It has no hardware key protection, no attested device identity,
no hardened endpoint, no accredited cryptography and no independent assessment. Those are not
incremental improvements — they are the gap between a demonstration and a system that could be trusted
with real material.
