# Demonstration guide

The point of this system is one trustworthy cycle. Present it in this order.

## Before you start

```powershell
# terminal 1
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000

# terminal 2
cd frontend && npm run dev
```

Sign in as `COMMANDER-001` / `Commander!2026`.

Have the automated run ready as a fallback — it prints every result you are about to describe:

```powershell
.\.venv\Scripts\python.exe scripts\demo_end_to_end.py
```

---

## 1. The problem, in one sentence

"Every recipient of an encrypted document ends up with identical plaintext, so when a copy leaks
nothing in it says who decrypted it."

Open **COMMAND CENTRE** and point at the KPI row: three documents, several active recipients, one
shared ledger.

---

## 2. Two recipients, same document, different forensic identity

1. Go to **DOCUMENTS**. Open `SYNTHETIC SECURE BRIEF 001`. Note the classification, the version hash
   and who holds need-to-know.
2. In the decryption panel, press **DECRYPT** as `RECIPIENT-001`.
3. Note the session id, the watermark tag, the PSNR/SSIM figures and that the event was committed.
4. Sign out, sign in as `RECIPIENT-002`, decrypt the same document.
5. **The watermark tags differ. The document is identical.**

> Say this out loud: *"Visually identical, forensically distinct. The difference is invisible until
> someone leaks a copy."*

The PSNR/SSIM figures are measured, not claimed. Do not round them to "identical".

---

## 3. The leak

1. Sign back in as `INVESTIGATOR-001`.
2. Go to **FORENSICS**, open an investigation, and submit one of the recipient copies from
   `data/evidence/recipient_copies/RECIPIENT-001/`.
3. Walk the evidence chain top to bottom. Every hop should be green.
4. The outcome reads `VERIFIED ASSOCIATION` with the recipient, session and version.

> Land the boundary explicitly: *"This proves the copy is cryptographically linked to that
> decryption session. It does not prove the person leaked it."*

---

## 4. Break it, honestly

Press **RUN SECURITY DEMONSTRATION** on the command centre, or use **SECURITY LAB**.

Show these four in order:

| Simulation | Result |
|---|---|
| Ledger tampering | Storage guard refuses the first write; after the guard is removed, `LEDGER INTEGRITY: TAMPER DETECTED` and the node is reported divergent |
| Service-key forgery | `SIGNATURE INVALID` — the service cannot manufacture attribution |
| Replay | `REPLAY ATTACK DETECTED` |
| Watermark corruption | `WATERMARK NOT RECOVERED` — nobody is blamed |

The fourth is the important one. **A system that always returns a match is worse than one that does
not**, because it manufactures false accusations.

---

## 5. Operational controls

1. **Two-person control** — raise an evidence export as `INVESTIGATOR-001`, approve once, then show
   the export is still refused (`TWO_PERSON_APPROVAL_REQUIRED`). Add a second *different* identity.
2. **Emergency lockdown** — as `COMMANDER-001`, engage it. The banner appears and every decryption is
   refused with `EMERGENCY LOCKDOWN ACTIVE`. Show the audit trail is still readable: lockdown blocks
   access, it does not destroy evidence.
3. **Revocation** — as `SECURITY-001`, revoke `RECIPIENT-002`. Their next attempt is refused
   immediately, while their earlier session records remain intact.
4. **Need-to-know above clearance** — `RECIPIENT-003` holds TOP_SECRET clearance and is still refused
   the brief. Say why: clearance is necessary, not sufficient.

---

## 6. Assurance

1. **SECURITY LAB** → watermark probe: show the measured recovery across PDF re-save, JPEG quality 70,
   a 50% downscale and a 150% upscale.
2. **LEDGER** → press **VERIFY LEDGER**. Show per-node verdicts, recomputed hashes, Merkle proofs and
   the agreement check.
3. **AUDIT** as `AUDITOR-001` — read-only. Show the auditor can verify everything and change nothing.
4. **AI INTELLIGENCE** — show the label `AI-ASSISTED ANALYSIS`, or `AI SERVICE OFFLINE` if no local
   model is running, and confirm every security verdict is unchanged either way.

---

## If you are asked hard questions

**"Is this production ready?"**
No. It is a working prototype. See `docs/PRODUCTION_GAPS.md`.

**"Can someone just photograph the screen?"**
Yes. No software control prevents that on a compromised endpoint. The watermark still identifies
which session the material came from, which is what makes the photograph actionable.

**"What if the administrator is the attacker?"**
They cannot forge a recipient's signature, they cannot write to the append-only ledger, they cannot
approve their own request and they cannot delete an audit record. Demonstrate this in the lab.

**"Is the watermark unbreakable?"**
No. It survives the transformations we measured and we report the ones it does not. Heavy cropping
and angled photography are expected to defeat it, and the system says `NOT FOUND` rather than
guessing.

**"What is NIST-approved here?"**
ML-KEM-768 and ML-DSA-65 through `pqcrypto`'s compiled PQClean implementation. Document content uses
AES-256-GCM, which is the correct primitive for bulk data — labelling AES as post-quantum would be
wrong.
