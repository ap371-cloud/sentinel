# Limitations

Every limitation in one place, without hedging. Several of these are accepted residual risk that no
amount of additional engineering in this codebase would close.

---

## 1. The fundamental one

**A verified association is not proof that a person leaked the document.**

The system proves a cryptographic link between a recovered copy and an authorised decryption session. A
session is a cryptographic event. A leaked copy is a physical-world event. Bridging the two would require
proving that a specific human performed a specific action at a specific time on a specific machine, and
no watermark or ledger can do that.

This appears in the interface, in every evidence report's attestation and limitations block, and in the
commander's guide.

## 2. Endpoint capture

**No software control prevents a user photographing, screenshotting or transcribing displayed content.**

The watermark means such a capture is *attributable* rather than *prevented*. That is a real and useful
property, and it is categorically weaker than prevention.

OS-level capture control is technically possible on some platforms and is not implemented here.
`docs/PRODUCTION_GAPS.md` lists it as required production work.

## 3. Watermark robustness boundaries

Measured and recovered from: clean, PDF re-save, JPEG quality 70, 50% downscale, 150% upscale,
re-import after canonicalisation. **6 of 6.**

Not tested, and not claimed to survive:

- Angled photography
- Heavy cropping
- Print/scan on real hardware
- Image-model regeneration
- Low-quality rescanning chains

In those cases the system reports `WATERMARK NOT RECOVERED` or `WEAK MATCH`. That is the correct and
honest outcome, and a test asserts it so it cannot silently regress.

## 4. Collusion

Two recipients who compare their copies can difference them to estimate the embedding pattern, and
potentially forge a mark.

Collusion-resistant watermarking is a separate research problem, not an engineering task. It is not
implemented.

## 5. Coercion

A user acting under duress completes a technically perfect, fully authorised flow. Every check passes,
the signature is valid, the ledger record is complete.

Nothing here detects coercion. This is an accepted residual risk.

## 6. Key custody

The watermark root secret is a single 256-bit value in the encrypted key vault. It protects **every**
watermark derivation in the deployment.

- If it leaks, watermark tags for the entire deployment can be forged.
- By default its key-encryption key comes from a local file, which offers no protection against an
  attacker who already holds the machine.

Production requires hardware-backed non-exportable keys with split custody. This is the most
consequential single gap in the system.

## 7. Device trust

A device fingerprint is asserted by the client. A determined attacker who knows a valid device id can
present it.

This is labelled `SIMULATED DEVICE IDENTITY` in code, the API and the interface. Production requires TPM
or Secure-Enclave attestation.

## 8. Ledger independence

Three replicas exist as separate database files on one host. That makes single-file tampering detectable
in principle, but real independence means separate hosts or containers with separate trust. A host-level
compromise reaches all three.

The consensus is deterministic proposer rotation, which behaves correctly for three nodes and is
documented as not being a formally reviewed BFT protocol.

A quorum of 2 of 3 tolerates one compromised node. It does not tolerate two.

## 9. Audit integrity under host compromise

Audit records are hash-chained and anchored into the ledger, which is the right design. But anyone with
write access to the whole host can delete records before the chain is inspected. Prevention of deletion
requires storage media or a separate trust domain that this prototype does not have.

## 10. Physical and analog channels

- A printed page carries no session mark.
- A photograph displayed on another screen carries the mark of what was photographed, which is useful,
  but the capture conditions are unbounded.
- Handwritten transcription of content leaves no trace at all.

Physical security is entirely out of scope.

## 11. Performance

Watermarking dominates the cost: roughly one second per page for embedding, and a few seconds for blind
extraction. A long document is slow.

Extraction currently iterates candidate document versions. That is acceptable for a handful of
documents and needs a shortlist for a large corpus. These are throughput problems, not security
problems.

## 12. No abuse controls

No rate limiting, no quotas, no resource isolation. An authorised user can generate unbounded sessions
and inflate the ledger. Anomaly detection *reports* unusual volume; it does not prevent it.

## 13. Authentication strength

PBKDF2-HMAC-SHA256 at 240k iterations is acceptable for a prototype and behind current guidance for
production, which favours Argon2id or scrypt. There is no second factor. Account lockout is a fixed
counter rather than risk-based throttling.

## 14. No independent assurance

- No external cryptographic validation
- No penetration test
- No red team exercise
- No formal verification of the authorisation engine
- No supply-chain review
- No Fuzzing of PDF parsing or input handling

The test suite is the author's own and proves the author's own assumptions hold.

## 15. Operational maturity

No incident response runbooks, no on-call, no recovery drill, no retention policy, no training, no
change control, no legal review of the reporting process.

## 16. Classification labels

`UNCLASSIFIED`, `RESTRICTED`, `CONFIDENTIAL`, `SECRET`, `TOP_SECRET` are **application strings** in this
prototype. They do not reproduce any official classification scheme and carry no accreditation. Do not
present them as classification markings.

## 17. Local AI

Optional, advisory, and never a decision input. It has not been evaluated for information leakage in a
classified context. If it is running on the same host as protected material, that is a deployment
decision with a risk trade-off, not a solved problem.

## 18. What the prototype is for

Demonstrating that the chain works, honestly fails when it should, and never manufactures an
accusation.

It is **not** a system that should be trusted with real protected material. That gap is documented in
`docs/PRODUCTION_GAPS.md`, and it is a gap in hardware, process and independent proof — not in the
amount of code.
