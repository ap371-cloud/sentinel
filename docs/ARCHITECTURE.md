# Architecture

## 1. System overview

```mermaid
graph TB
  subgraph TERMINAL["COMMAND TERMINAL — 127.0.0.1 only"]
    UI[React command interface]
  end

  subgraph API["FastAPI boundary"]
    GUARDS[Auth + RBAC + read/write guards]
    ROUTES[Route handlers]
  end

  subgraph CORE["Core security services"]
    POLICY[Policy engine<br/>RBAC + ABAC]
    IDENTITY[Identity service]
    DEVICE[Device trust]
    DOCS[Document service]
    CRYPTO[Crypto service]
    SESSION[Decryption session service]
    WATERMARK[Watermark engine]
    EVENTS[Signed event service]
  end

  subgraph LEDGER["Offline permissioned ledger"]
    NA[NODE-A]
    NB[NODE-B]
    NC[NODE-C]
  end

  subgraph OPS["Security operations"]
    INCIDENT[Incident engine]
    ANOMALY[Anomaly rules]
    LOCKDOWN[Lockdown]
    REVOKE[Revocation]
    LAB[Attack laboratory]
  end

  FORENSIC[Forensic engine]
  AI[Local AI — optional]
  AUDIT[Audit chain]

  UI --> GUARDS --> ROUTES
  ROUTES --> POLICY
  ROUTES --> IDENTITY
  ROUTES --> DOCS
  ROUTES --> SESSION
  SESSION --> DEVICE
  SESSION --> CRYPTO
  SESSION --> WATERMARK
  SESSION --> EVENTS
  EVENTS --> LEDGER
  EVENTS --> AUDIT
  LEDGER --> FORENSIC
  FORENSIC --> INCIDENT
  INCIDENT --> ANOMALY
  ROUTES --> LOCKDOWN
  ROUTES --> REVOKE
  ROUTES --> LAB
  INCIDENT -.summarisation only.-> AI
```

Trust boundaries, stated plainly:

1. **Browser ↔ backend** — loopback only; the runtime egress guard refuses anything else.
2. **Backend ↔ ledger nodes** — separate processes would be separate hosts in production; here each
   node owns a separate database file so a single-file compromise is not a whole-ledger compromise.
3. **Backend ↔ local AI** — one-way. The model reads verified summaries and returns advisory text. It
   cannot influence any decision.
4. **Key vault** — separate storage from the operational database, so reading the database does not
   reveal key material.

---

## 2. Identity and authentication flow

```mermaid
sequenceDiagram
  participant T as Terminal
  participant A as API
  participant I as Identity service
  participant K as Key vault

  T->>A: POST /auth/login
  A->>I: authenticate(id, passphrase, device_id)
  I->>I: verify PBKDF2-HMAC-SHA256 (240k iterations)
  I->>I: check account status is ACTIVE
  I->>I: check device registered, active, trusted
  I->>I: issue HMAC-signed bearer token, 8h
  I->>K: read public signing key (never the secret)
  I-->>T: token + identity + device list
```

Every subsequent request re-reads the account from the database. A token that is still valid cannot
outlive a revocation, because authorisation never trusts the token's cached claims.

---

## 3. Authorisation: fourteen checks, deterministic

```mermaid
flowchart TD
  START[Decryption request] --> N{nonce issued,<br/>unconsumed, unexpired,<br/>owner matches?}
  N -- no --> REPLAY[REPLAY ATTACK DETECTED]
  N -- yes --> A{account ACTIVE?}
  A -- no --> DENY[ACCESS DENIED]
  A -- yes --> G{need-to-know grant<br/>present?}
  G -- no --> DENY
  G -- yes --> C{clearance >=<br/>classification?}
  C -- no --> DENY
  C -- yes --> U{unit in scope?}
  U -- no --> DENY
  U -- yes --> R{role permitted by<br/>document policy?}
  R -- no --> DENY
  R -- yes --> D{device registered,<br/>active, trusted, owned?}
  D -- no --> DEV[DEVICE NOT AUTHORIZED]
  D -- yes --> V{document SEALED,<br/>unexpired?}
  V -- no --> DENY
  V -- yes --> K{signing and KEM keys<br/>usable, unexpired?}
  K -- no --> DENY
  K -- yes --> B{session budget<br/>remaining?}
  B -- no --> DENY
  B -- yes --> O{offline operation<br/>permitted by policy?}
  O -- no --> DENY
  O -- yes --> L{lockdown active<br/>without break-glass?}
  L -- yes --> LOCK[EMERGENCY LOCKDOWN ACTIVE]
  L -- no --> ALLOW[PROCEED]
```

Each check returns a reason code such as `NEED_TO_KNOW_MISSING` or `CLEARANCE_BELOW_SECRET`. The full
trace is stored on the session and shown in the UI, so a refusal is always explainable.

---

## 4. Document lifecycle

```mermaid
stateDiagram-v2
  [*] --> CREATED
  CREATED --> CLASSIFIED
  CLASSIFIED --> APPROVED
  APPROVED --> DISTRIBUTED
  DISTRIBUTED --> ACTIVE
  ACTIVE --> EXPIRED
  ACTIVE --> REVOKED
  EXPIRED --> ARCHIVED
  REVOKED --> ARCHIVED
  ARCHIVED --> [*]
```

Lifecycle state is separate from access availability (`SEALED`, `SUSPENDED`, `REVOKED`) because a
document can be `ARCHIVED` yet still have been `ACTIVE` when it leaked, and the forensic record must
show which.

Every transition writes an audit record. Illegal transitions raise rather than silently succeed.

---

## 5. Encryption and key wrapping

```mermaid
graph LR
  PLAIN[Normalised PDF] --> HASH[SHA-256 content hash]
  HASH --> SEAL[AES-256-GCM seal<br/>random DEK, hash bound as AAD]
  DEK[DEK 32 bytes] --> SEAL
  SEAL --> STORE[(sealed artefact)]

  DEK --> W1[wrap for RECIPIENT-001<br/>ML-KEM-768 → HKDF → AES-GCM]
  DEK --> W2[wrap for RECIPIENT-002<br/>ML-KEM-768 → HKDF → AES-GCM]

  STORE --> SEALED[Sealed artefact:<br/>one ciphertext]
  W1 --> KEYS[Per-recipient key wraps]
  W2 --> KEYS
```

This is the broadcast model from the problem statement: **encrypt once, many recipients**. The
post-quantum KEM is what makes a recipient's copy of the content key something only that recipient can
unwrap.

The document id, version id and content hash are bound in as AEAD associated data, so a ciphertext
moved to a different document or a different declared hash fails to decrypt rather than decrypting to
something that is then checked.

---

## 6. Watermark generation and embedding

```mermaid
flowchart TD
  S[Session: recipient, document,<br/>hash, session_id, fresh nonce] --> HMAC[HMAC-SHA256 over<br/>canonical inputs]
  ROOT[Vault-held root secret] --> HMAC
  HMAC --> TAG[64-bit opaque tag]
  TAG --> ECC[80-bit payload<br/>tag + CRC-16]
  ECC --> SPREAD[Keyed carrier pattern<br/>from root + document identity]
  SPREAD --> DCT[8x8 block DCT,<br/>mid-frequency coefficients]
  DCT --> FIT[Range fit to avoid clipping]
  FIT --> PDF[Watermarked PDF]
```

Key properties:

- **Opaque.** The tag is an HMAC output. It contains no readable identity and requires an authorised
  registry lookup to interpret.
- **Session-specific.** A fresh nonce and the session id are inside the derivation, so the same
  recipient opening the same document twice gets two different tags.
- **Carriers keyed to document identity, not to the file.** That is what makes extraction blind and
  survives edits to the leaked copy.
- **Bit value rides on the correlation sign**, so a zero bit is an inverted excursion, not a missing
  one.

---

## 7. Extraction and confidence

```mermaid
flowchart TD
  FILE[Suspected copy] --> RASTER[Rasterise at fixed DPI]
  RASTER --> SCALE[Canonicalise across<br/>candidate scale factors]
  SCALE --> KEYED[Rebuild carriers from<br/>root + candidate document]
  KEYED --> CORR[Correlate per payload bit]
  CORR --> SIGMA[Noise floor from<br/>within-bit carrier spread]
  SIGMA --> CNR[Carrier-to-noise ratio]
  CNR --> DECIDE[Soft decide +<br/>CRC integrity check]
  DECIDE --> LOOKUP[Registry lookup over<br/>candidate versions]
  LOOKUP --> VERDICT{Verdict}
  VERDICT -->|exact tag, CNR >= threshold| FOUND[FOUND]
  VERDICT -->|near miss, CNR >= weak threshold| WEAK[WEAK MATCH]
  VERDICT -->|payload valid, unknown tag| CORRUPTED[CORRUPTED]
  VERDICT -->|no carrier energy| NOTFOUND[NOT FOUND]
```

The noise floor is estimated **within** each bit's carrier set. Measuring spread across bits would
mistake the signal itself for noise, which is exactly the mistake that made an earlier version of this
engine report implausible confidence figures.

Confidence is capped below 1.0 by design. A recovered watermark is strong evidence, never certainty.

---

## 8. Signed events

```mermaid
graph LR
  CORE[Event fields including<br/>watermark tag] --> CANON[Canonical JSON<br/>sorted keys, fixed encoding]
  CANON --> HASH[SHA-512]
  HASH --> SIGN[ML-DSA-65 sign<br/>with recipient's key]
  SIGN --> STORE[(Event row)]
  HASH --> CHAIN[prev_event_hash<br/>hash chain]
  STORE --> TX[Ledger transaction]
  TX --> MERKLE[Merkle inclusion proof]
```

The watermark tag is inside the signed payload. Without it, a recipient could argue the fingerprint
was added after they signed, which would undermine the attribution entirely.

Events are chained by `prev_event_hash`, and the event row is written **after** the ledger accepts
the transaction, so the table needs no update and stays genuinely append-only.

---

## 9. Ledger

```mermaid
graph TB
  subgraph CONSENSUS["Deterministic rotation + quorum of 2 of 3"]
    P[Proposer builds block]
    V1[NODE-A validates and votes<br/>ML-DSA-65]
    V2[NODE-B validates and votes]
    V3[NODE-C validates and votes]
    P --> V1 & V2 & V3
    V1 & V2 --> COMMIT[Commit on quorum]
  end
  COMMIT --> B1[(NODE-A chain)]
  COMMIT --> B2[(NODE-B chain)]
  COMMIT --> B3[(NODE-C chain)]
```

A node independently validates that the proposal extends *its own* chain, so a malicious proposer
cannot fork a node silently.

**Verification** recomputes, per node: chain linkage, Merkle root from stored transactions, block
hash, running state root, block signature and every quorum vote signature. It then compares state
roots across nodes. A node that recomputed only its own block hash still fails, because the Merkle
root and the signatures are recomputed too.

**Below quorum**, events are queued locally rather than dropped. On reconnection they replay through
the same validation path; anything already present is recorded as such, and genuine conflicts are
recorded without overwriting either copy.

---

## 10. Forensic investigation

```mermaid
graph TD
  LEAK[Suspected copy] --> H1[File hash + preservation]
  H1 --> H2[Blind watermark extraction]
  H2 --> H3[Registry lookup]
  H3 --> H4[Session record]
  H4 --> H5[Recipient association]
  H5 --> H6[ML-DSA signature verification]
  H6 --> H7[Ledger transaction lookup]
  H7 --> H8[Merkle inclusion proof]
  H8 --> H9[Document version integrity]
  H9 --> REPORT[Hashed evidence report]
```

Document integrity uses page-image comparison against the stored pre-encryption render with a
documented PSNR floor. A watermarked but otherwise untouched copy sits near 41 dB; an edited copy
falls below the floor and is reported as `DOCUMENT_MODIFIED`.

The final outcome is one of: `VERIFIED ASSOCIATION`, `PARTIALLY VERIFIED`, `DOCUMENT MODIFIED`,
`WATERMARK NOT RECOVERED`, `NO MATCH FOUND`, `SIGNATURE INVALID`, `LEDGER PROOF INVALID`,
`INSUFFICIENT EVIDENCE`. A partial result is never upgraded.

---

## 11. AI boundary

```mermaid
graph LR
  DET[Deterministic detection] --> STRUCT[Structured verified facts]
  STRUCT --> LLM[Local model]
  LLM --> NARR[Advisory narrative]
  NARR --> UI[Labelled AI-ASSISTED ANALYSIS]

  DET -.never.-> LLM
  LLM -.never.-> ALLOW[Authorisation / signature /<br/>ledger / forensic verdict]
```

The model receives aggregated, already-verified metadata. It never sees plaintext document content,
and it cannot execute privileged actions. If it is unavailable the platform is unaffected.

---

## 12. Module boundaries

| Package | Owns | Never does |
|---|---|---|
| `core/` | Configuration, policy decisions, crypto primitives, egress guard | Touch the database |
| `crypto/` | PQC provider, key vault, canonical signing, hashing | Decide authorisation |
| `documents/` | Rendering, authenticated encryption, versioning | Emit security events |
| `watermark/` | Derivation, coding, embedding, extraction, verdicts | Know about recipients |
| `ledger/` | Blocks, Merkle proofs, nodes, quorum, verification | Sign on behalf of recipients |
| `forensic/` | Analysis, evidence, reports | Re-embed watermarks |
| `security/` | Incidents, anomalies, lockdown, revocation, attack lab | Bypass the policy engine |
| `services/` | Orchestration and transactions | Implement cryptography |
| `api/` | Transport, validation, guards | Contain business logic |

The watermark engine has no knowledge of recipient identities — it takes a derived tag and a document
reference. That is what makes the same engine usable for embedding and for blind extraction.
