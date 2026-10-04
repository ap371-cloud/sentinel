# Threat model

Format: **Threat → Impact → Control → Detection → Evidence → Remaining limitation.**

Honesty note up front: several of these have real residual risk that software does not close. Those are
stated rather than smoothed over.

---

## 1. Compromised user account

| | |
|---|---|
| **Threat** | An attacker obtains a recipient's passphrase and uses it. |
| **Impact** | Unauthorised decryption of every document that recipient may read, each with a valid watermark. |
| **Control** | PBKDF2-HMAC-SHA256 at 240k iterations, per-user salt, constant-time comparison. Account lockout after five failures. Device binding. |
| **Detection** | `AUTHENTICATION_ANOMALY` rule on repeated failures; lockout raises an event. |
| **Evidence** | Audit records every attempt with outcome; lockout timestamped. |
| **Limitation** | A correct passphrase from a trusted device is indistinguishable from the legitimate user. The watermark attributes the **session**, not the person. |

## 2. Compromised device / endpoint

| | |
|---|---|
| **Threat** | Malware or a physical attacker controls the machine after decryption is authorised. |
| **Impact** | Plaintext is available to the attacker. Screen capture, photography, transcription. |
| **Control** | Session-specific watermark means whatever leaves is attributable to that session. Signed event records device context. |
| **Detection** | `DEVICE_IDENTITY_CHANGE` when an unregistered device appears; device trust state changes are logged. |
| **Evidence** | Device id, trust state and last-seen recorded on the session. |
| **Limitation** | **No software control prevents this.** A watermark is not a data-loss-prevention mechanism. |

## 3. Stolen or copied private key

| | |
|---|---|
| **Threat** | The recipient's ML-DSA secret key is exfiltrated from the key vault. |
| **Impact** | An attacker can sign decryption events that verify against the recipient's public key. |
| **Control** | Keys encrypted at rest under a scrypt-derived KEK. Key lifecycle with revocation. Revoking the key stops future signing. |
| **Detection** | Key revocation raises a `KEY_COMPROMISE` event; related sessions are flagged. |
| **Evidence** | Key metadata with version, status and timestamps. Historical events remain valid. |
| **Limitation** | Events signed by a compromised key before revocation cannot be distinguished from legitimate ones. Revocation date bounds the doubt, it does not remove it. |

## 4. Malicious or compromised administrator

| | |
|---|---|
| **Threat** | An administrator with database and configuration access acts against the organisation's interest. |
| **Impact** | Fabricated attribution, hidden access, altered audit history. |
| **Control** | Separation of duties: DOCUMENT_ADMIN holds no evidence, ledger-write, approval or incident authority. Two-person control with the requester barred from approving. Append-only storage guards on security-bearing columns. Append-only audit chain. |
| **Detection** | Cross-node state-root comparison. Audit chain verification. `ADMIN FORGERY REJECTED` in the attack laboratory. |
| **Evidence** | Privileged actions hash-chained and anchored into the ledger. |
| **Limitation** | An administrator can still create accounts, change classification, or delete unsealed working files. Those actions are auditable, not preventable. |

## 5. Compromised ledger node

| | |
|---|---|
| **Threat** | An operator with access to one node's database alters its stored blocks. |
| **Impact** | One replica's history diverges from the quorum. |
| **Control** | Storage-level immutability guards. Block signatures. Merkle roots recomputed from stored transactions. Quorum certificates. Running state root. |
| **Detection** | Node's own recomputation fails **and** cross-node state roots disagree. Reported as `CONSISTENCY FAILURE`. |
| **Evidence** | Both verdicts retained; conflicting records preserved on every node. |
| **Limitation** | A majority-compromised node set defeats a majority-based consensus. The design assumes the node set is known and not simultaneously compromised. |

## 6. Replayed request

| | |
|---|---|
| **Threat** | A captured decryption authorisation is replayed. |
| **Impact** | A second authorised decryption obtained from a stolen request. |
| **Control** | Server-issued single-use nonce bound to identity and document, with short expiry. |
| **Detection** | `REPLAY_ATTACK_DETECTED`, security event raised, request refused. |
| **Evidence** | Both the original and the replay attempt are in the audit trail. |
| **Limitation** | Replay within the nonce's validity window is possible only if the nonce has not yet been consumed. The window is 45 seconds. |

## 7. Watermark removal or forgery

| | |
|---|---|
| **Threat** | An attacker strips the watermark, or transplants a different one. |
| **Impact** | Attribution is lost, or wrongly transferred to an innocent recipient. |
| **Control** | Tag is an HMAC under a vault-held root; carriers are keyed to document identity. Extraction validates against the registry and reports Hamming distance. |
| **Detection** | `WATERMARK NOT RECOVERED` for a stripped mark; a transplanted mark matches no registered session. |
| **Evidence** | Recovery verdict with carrier-to-noise ratio and bit-error estimate. |
| **Limitation** | **Collusion.** Two recipients who difference their copies can estimate the embedding pattern. Collusion-resistant watermarking is a separate research problem. Also, heavy cropping and angled photography defeat the mark. |

## 8. Modified leaked document

| | |
|---|---|
| **Threat** | The leaked copy is edited before or after it leaks. |
| **Impact** | A false attribution, or a missed one. |
| **Control** | Page-image comparison against the stored pre-encryption render with a documented PSNR floor. |
| **Detection** | Below the floor the outcome is `DOCUMENT MODIFIED` or `WATERMARK NOT RECOVERED` — never accepted. |
| **Evidence** | Per-page PSNR values in the evidence chain and the report. |
| **Limitation** | Someone could edit content *and* re-embed a valid watermark if they obtained the root secret. That is a key-compromise scenario, not a watermark failure. |

## 9. Tampered evidence or report

| | |
|---|---|
| **Threat** | An investigator or insider edits stored evidence or a generated report. |
| **Impact** | A finding that misrepresents what was analysed. |
| **Control** | Evidence preserved with its hash before analysis; analysis never mutates the stored copy; reports are hashed. Storage guards on custody columns. |
| **Detection** | Report integrity recomputation returns `FAILED` after any edit. |
| **Evidence** | Chain of custody records who collected, who analysed, when, with which tool version. |
| **Limitation** | Whoever controls the storage can delete a whole record. The registry row is one anchor; the signed ledger event is the durable one. |

## 10. Watermark exhaustion or guessing

| | |
|---|---|
| **Threat** | An attacker guesses a valid tag to frame a recipient. |
| **Impact** | False attribution. |
| **Control** | 64-bit HMAC-SHA256 output under a secret root key. Registry lookup requires a match across a keyed candidate space. |
| **Detection** | A guessed tag matching no registered session yields `NO MATCH FOUND`. |
| **Evidence** | Hamming distance and confidence recorded. |
| **Limitation** | 64 bits makes exhaustive search infeasible, but the tag is not a research-grade construction. |

## 11. Database modification outside the application

| | |
|---|---|
| **Threat** | Direct SQL editing by someone with file access. |
| **Impact** | Rewritten operational records. |
| **Control** | SQLite triggers refuse updates to security-bearing columns and all deletes. |
| **Detection** | The write itself fails; where guards are removed, hash chains and ledger verification detect the change. |
| **Evidence** | The attack laboratory records both the refused write and the detected forgery. |
| **Limitation** | Anyone with file access can drop a trigger. That is why verification must be able to run independently of the application. |

## 12. Offline node divergence

| | |
|---|---|
| **Threat** | A node is unreachable or restored from a stale backup. |
| **Impact** | Ledger replicas disagree. |
| **Control** | Queued events rather than dropped ones. State roots compared across nodes. |
| **Detection** | `CONSISTENCY FAILURE` naming divergent nodes. `LEDGER_DIVERGENCE` security event. |
| **Evidence** | Both histories preserved; nothing overwritten. |
| **Limitation** | Resolution is manual and requires authorised review. That is deliberate. |

## 13. AI hallucination or misuse

| | |
|---|---|
| **Threat** | The local model invents a fact, or is used to influence a decision. |
| **Impact** | Misleading narrative presented as a security finding. |
| **Control** | The model has no decision authority. It receives only already-verified structured metadata, never document content. Output labelled `AI-ASSISTED ANALYSIS`. |
| **Detection** | Deterministic verdicts are returned alongside every AI response for comparison. |
| **Evidence** | The deterministic result is shown next to the narrative, always. |
| **Limitation** | A human may still over-trust a fluent summary. The labelling is the mitigation, not a guarantee. |

## 14. Incorrect policy configuration

| | |
|---|---|
| **Threat** | A classification or scope is set wrongly, granting or denying access improperly. |
| **Impact** | Unauthorised access, or a legitimate recipient blocked. |
| **Control** | Policy changes are high-risk actions under two-person control. Every change is audit-recorded with a reason. |
| **Detection** | Denials carry a reason code, so misconfiguration is visible in the refusal pattern. |
| **Evidence** | Audit chain entry with the change, the actor and the justification. |
| **Limitation** | The system cannot tell a sensible policy from a mistaken one. That remains a command decision. |

## 15. Coerced access

| | |
|---|---|
| **Threat** | A legitimate user is compelled to decrypt. |
| **Impact** | Fully authorised decryption with a valid watermark. |
| **Control** | Break-glass exists for legitimate emergencies. Nothing detects duress. |
| **Detection** | None available. |
| **Evidence** | The decryption is recorded normally. |
| **Limitation** | **Not addressed.** A coerced user produces a technically perfect record. This is a known and accepted residual risk. |

## 16. Denial of service

| | |
|---|---|
| **Threat** | An authorised user floods decryption, or a node is taken down. |
| **Impact** | Ledger bloat; degraded availability. |
| **Control** | Document policies support a maximum session count and access expiry. Quorum tolerates one node. |
| **Detection** | `UNUSUAL_DECRYPTION_ACTIVITY` above the documented rate. |
| **Evidence** | Session and anomaly records. |
| **Limitation** | No rate limiting, quota enforcement or resource isolation. |

## 17. Physical security and insider access to paper

| | |
|---|---|
| **Threat** | A printed copy or photograph leaves the controlled environment. |
| **Impact** | Content disclosed with no watermark correlation. |
| **Control** | Watermarking applies to the digital artefact at decryption. Document policy can forbid printing and export. |
| **Detection** | Not detectable by this system. |
| **Evidence** | None. |
| **Limitation** | **Out of scope.** A printed page carries no session mark. |

---

## Residual risk summary

Ranked by how much they should worry a reviewer:

1. **Endpoint compromise** — cannot be mitigated by software. Requires hardened endpoints and a
   controlled viewer.
2. **Collation attack on the watermark** — inherent to per-session watermarking without collusion-
   resistant coding.
3. **Coercion** — produces a technically perfect record and is undetectable.
4. **Majority node compromise** — a quorum assumption, not a proof.
5. **Physical and analog channels** — out of scope entirely.
