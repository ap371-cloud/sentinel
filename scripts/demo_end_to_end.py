"""End-to-end demonstration of the critical forensic chain.

Runs entirely against the local database with no network access:

    authorised decryption -> unique session -> unique forensic watermark ->
    signed event -> offline ledger -> leaked file -> blind watermark extraction
    -> session match -> version check -> signature verification -> ledger and
    Merkle verification -> hashed evidence report

It then deliberately breaks the system and asserts that each failure is
detected rather than absorbed.

    python scripts/demo_end_to_end.py
"""

from __future__ import annotations

import shutil
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

#: Storage is cleared *before* the application modules are imported. The key
#: vault is constructed at import time and caches its key-encryption key, so
#: deleting the files afterwards would leave it holding a key that no longer
#: matches what is on disk.
for _folder in ("data", "ledger", "evidence", "keys"):
    _target = ROOT / _folder
    if _target.exists():
        shutil.rmtree(_target, ignore_errors=True)
    _target.mkdir(parents=True, exist_ok=True)

from app.core.config import PATHS, DeviceTrust  # noqa: E402
from app.core.exceptions import (  # noqa: E402
    ApprovalRequired,
    DeviceNotAuthorized,
    ForgeError,
    LockdownActive,
    RecipientRevoked,
    ReplayDetected,
)
from app.database.session import (  # noqa: E402
    create_node_schema,
    create_ops_schema,
    ops_session,
)
from app.ledger.chain import NETWORK  # noqa: E402
from app.security import incident_engine, lockdown, revocation  # noqa: E402
from app.security.attack_lab import ATTACK_SCENARIOS  # noqa: E402
from app.services import (  # noqa: E402
    approval_service,
    decryption_service,
    document_service,
    forensic_service,
    identity_service,
    seed_service,
)

PASS, FAIL = "  [PASS]", "  [FAIL]"
failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"{PASS} {label}{(' — ' + detail) if detail else ''}")
    else:
        failures.append(label)
        print(f"{FAIL} {label}{(' — ' + detail) if detail else ''}")


def step(number: int, text: str) -> None:
    print(f"\n{'-' * 78}\nSTEP {number}: {text}\n{'-' * 78}")


def bootstrap() -> None:
    step(1, "Initialise storage, ledger nodes and synthetic identities")
    create_ops_schema()
    for node_id in NETWORK.node_ids:
        create_node_schema(node_id)
    NETWORK.ensure_ready()
    with ops_session() as session:
        summary = seed_service.seed(session)
    print(f"  identities created : {summary['users_created']}")
    print(f"  devices created    : {summary['devices_created']}")
    print(f"  documents created  : {summary['documents_created']}")
    print(f"  units              : {summary['units']}")
    check("synthetic environment seeded", bool(summary["users_created"] and summary["documents_created"]))


def main() -> int:
    PATHS.ensure()
    bootstrap()

    with ops_session() as session:
        brief = session.query(document_service.Document).filter(
            document_service.Document.title == "SYNTHETIC SECURE BRIEF 001"
        ).one()
        document_id = brief.document_id
        print(f"\n  document under test: {document_id} ({brief.classification})")

        step(2, "Authorised decryption by RECIPIENT-001")
        recipient_one = identity_service.get(session, "RECIPIENT-001")
        token_one = identity_service.authenticate(
            session, recipient_id="RECIPIENT-001", password="Recipient1!2026",
            device_id="DEV-RECIPIENT-001-A",
        )[1]
        check("recipient authenticated", bool(token_one))
        nonce_one = decryption_service.issue_nonce(
            session, recipient_id="RECIPIENT-001", document_id=document_id
        )
        session_one = decryption_service.decrypt(
            session,
            actor=recipient_one,
            document_id=document_id,
            device_id="DEV-RECIPIENT-001-A",
            nonce=nonce_one["nonce"],
        )
        print(f"  session      : {session_one['session_id']}")
        print(f"  watermark    : {session_one['watermark_tag']}")
        print(f"  PSNR / SSIM  : {session_one['watermark_quality']['psnr_db']} dB / "
              f"{session_one['watermark_quality']['ssim']}")
        print(f"  signed event : {session_one['event_id']}")
        print(f"  ledger       : {session_one['ledger']['status']} in {session_one['ledger'].get('block_id')}")
        check("session created", bool(session_one["session_id"]))
        check("watermark embedded", session_one["watermark_quality"]["psnr_db"] > 35)
        check("event signed and committed", session_one["ledger"]["committed"])

        step(3, "Authorised decryption by RECIPIENT-002 of the same document")
        recipient_two = identity_service.get(session, "RECIPIENT-002")
        identity_service.authenticate(
            session, recipient_id="RECIPIENT-002", password="Recipient2!2026",
            device_id="DEV-RECIPIENT-002-A",
        )
        nonce_two = decryption_service.issue_nonce(
            session, recipient_id="RECIPIENT-002", document_id=document_id
        )
        session_two = decryption_service.decrypt(
            session,
            actor=recipient_two,
            document_id=document_id,
            device_id="DEV-RECIPIENT-002-A",
            nonce=nonce_two["nonce"],
        )
        print(f"  session      : {session_two['session_id']}")
        print(f"  watermark    : {session_two['watermark_tag']}")
        check("distinct sessions for the same document", session_one["session_id"] != session_two["session_id"])
        check(
            "distinct forensic watermarks per recipient",
            session_one["watermark_tag"] != session_two["watermark_tag"],
        )

        step(4, "Same recipient decrypting again yields a different watermark")
        nonce_one_again = decryption_service.issue_nonce(
            session, recipient_id="RECIPIENT-001", document_id=document_id
        )
        session_one_b = decryption_service.decrypt(
            session,
            actor=recipient_one,
            document_id=document_id,
            device_id="DEV-RECIPIENT-001-A",
            nonce=nonce_one_again["nonce"],
        )
        print(f"  session      : {session_one_b['session_id']}")
        print(f"  watermark    : {session_one_b['watermark_tag']}")
        check(
            "same recipient, second session, different watermark",
            session_one_b["watermark_tag"] != session_one["watermark_tag"],
        )

        step(5, "Replay of the consumed authorisation is refused")
        replayed = False
        try:
            decryption_service.decrypt(
                session,
                actor=recipient_one,
                document_id=document_id,
                device_id="DEV-RECIPIENT-001-A",
                nonce=nonce_one["nonce"],
            )
        except ReplayDetected:
            replayed = True
        check("REPLAY ATTACK DETECTED", replayed, "consumed nonce cannot be reused")

        step(6, "Simulate a leak from RECIPIENT-001's session and analyse it")
        leak_path = PATHS.render / "LEAKED_DOCUMENT.pdf"
        shutil.copy2(session_one["output_path"], leak_path)
        investigator = identity_service.get(session, "INVESTIGATOR-001")
        case = forensic_service.open_case(
            session,
            investigator=investigator,
            title="Suspected leak of synthetic secure brief",
            summary_text="Copy recovered outside the authorised distribution list.",
            suspected_document_id=document_id,
        )
        evidence = forensic_service.store_evidence(
            session,
            case=case,
            investigator=investigator,
            leaked_path=leak_path,
            original_filename="LEAKED_DOCUMENT.pdf",
        )
        analysis = forensic_service.analyze(session, evidence=evidence)
        print(f"  outcome    : {analysis['outcome']}")
        for link in analysis["evidence_chain"]:
            print(f"    {link['status']:<8} {link['link']:<26} {link['detail'][:74]}")
        check(
            "forensic association verified",
            analysis["outcome"] == "VERIFIED ASSOCIATION",
            analysis["outcome"],
        )
        check(
            "attributed to the correct recipient",
            analysis["matched_recipient_id"] == "RECIPIENT-001",
            str(analysis["matched_recipient_id"]),
        )
        check(
            "attributed to the correct session",
            analysis["matched_session_id"] == session_one["session_id"],
            str(analysis["matched_session_id"]),
        )
        check(
            "watermark confidence reported, not asserted as certainty",
            0 < analysis["watermark"]["confidence"] <= 1,
            f"confidence {analysis['watermark']['confidence']}",
        )

        report = forensic_service.build_report(session, evidence=evidence, investigator=investigator)
        integrity = forensic_service.verify_report_integrity(Path(report["report_path"]) if "report_path" in report else Path(evidence.report_path))
        print(f"  report hash: {report['report_sha256'][:32]}…")
        print(f"  integrity  : {integrity['status']}")
        check("evidence report hash verifies", integrity["status"].endswith("VERIFIED"))

        step(7, "Modified copy of the same leak is reported as altered")
        tampered = PATHS.render / "LEAKED_DOCUMENT_EDITED.pdf"
        document_service.pdf.build_pdf(
            [document_service.pdf.render_gray(leak_path)[0][:, :1400]],
            tampered,
        )
        edited_evidence = forensic_service.store_evidence(
            session,
            case=case,
            investigator=investigator,
            leaked_path=tampered,
            original_filename="LEAKED_DOCUMENT_EDITED.pdf",
        )
        edited = forensic_service.analyze(session, evidence=edited_evidence)
        print(f"  outcome    : {edited['outcome']}")
        for link in edited["evidence_chain"]:
            print(f"    {link['status']:<8} {link['link']:<26} {link['detail'][:74]}")
        check(
            "altered content detected rather than accepted",
            edited["outcome"] in ("DOCUMENT MODIFIED", "PARTIALLY VERIFIED", "WATERMARK NOT RECOVERED"),
            edited["outcome"],
        )

        step(8, "Watermark of the wrong session does not match")
        stranger_path = PATHS.render / "UNMARKED_COPY.pdf"
        shutil.copy2(Path(document_service.current_version(session, document_id).normalized_pdf_path), stranger_path)
        stranger_evidence = forensic_service.store_evidence(
            session,
            case=case,
            investigator=investigator,
            leaked_path=stranger_path,
            original_filename="UNMARKED_COPY.pdf",
        )
        stranger = forensic_service.analyze(session, evidence=stranger_evidence)
        print(f"  outcome    : {stranger['outcome']}")
        check(
            "unmarked copy is not attributed to anyone",
            stranger["outcome"] in ("WATERMARK NOT RECOVERED", "NO MATCH FOUND"),
            stranger["outcome"],
        )

        step(9, "Revoked recipient is refused immediately")
        revocation.revoke_recipient(
            session, recipient_id="RECIPIENT-002", actor_id="SECURITY-001",
            reason="Synthetic demonstration of rapid revocation",
        )
        revoked_refused = False
        try:
            nonce_three = decryption_service.issue_nonce(
                session, recipient_id="RECIPIENT-002", document_id=document_id
            )
            decryption_service.decrypt(
                session,
                actor=identity_service.get(session, "RECIPIENT-002"),
                document_id=document_id,
                device_id="DEV-RECIPIENT-002-A",
                nonce=nonce_three["nonce"],
            )
        except (RecipientRevoked, ForgeError) as exc:
            revoked_refused = True
            print(f"  refused    : {type(exc).__name__} — {exc}")
        check("REVOKED RECIPIENT refused", revoked_refused)

        step(10, "Unknown device is refused")
        unknown_refused = False
        try:
            nonce_four = decryption_service.issue_nonce(
                session, recipient_id="RECIPIENT-001", document_id=document_id
            )
            decryption_service.decrypt(
                session,
                actor=recipient_one,
                document_id=document_id,
                device_id="DEV-UNKNOWN-9999",
                nonce=nonce_four["nonce"],
            )
        except DeviceNotAuthorized as exc:
            unknown_refused = True
            print(f"  refused    : {type(exc).__name__} — {exc}")
        check("DEVICE NOT AUTHORIZED", unknown_refused)

        step(11, "Recipient with clearance but no need-to-know is refused")
        stranger_id = "RECIPIENT-003"
        if session.query(identity_service.Recipient).filter_by(recipient_id=stranger_id).first() is None:
            identity_service.create(
                session,
                recipient_id=stranger_id,
                display_name="Synthetic Recipient Three (TOP_SECRET, no grant)",
                role="RECIPIENT",
                unit="CHARLIE",
                clearance=4,
                password="Recipient3!2026",
                actor_id="ADMIN-001",
            )
        ntk_refused = False
        try:
            nonce_five = decryption_service.issue_nonce(
                session, recipient_id=stranger_id, document_id=document_id
            )
            decryption_service.decrypt(
                session,
                actor=identity_service.get(session, stranger_id),
                document_id=document_id,
                device_id="DEV-RECIPIENT-001-A",
                nonce=nonce_five["nonce"],
            )
        except ForgeError as exc:
            ntk_refused = True
            print(f"  refused    : {type(exc).__name__} — {exc}")
        check("NEED-TO-KNOW enforced above clearance", ntk_refused)

        step(12, "Two-person control: first approval alone is insufficient")
        approval = approval_service.request(
            session,
            action="EVIDENCE_EXPORT",
            requested_by="COMMANDER-001",
            justification="Synthetic demonstration of two-person control on evidence export",
            subject_id=case.case_id,
        )
        print(f"  request    : {approval['approval_id']} — {approval['status']}")
        first = approval_service.approve(
            session, approval_id=approval["approval_id"], approver_id="SECURITY-001",
            approver_role="SECURITY_OFFICER",
        )
        check(
            "one approval does not satisfy the control",
            not first["sufficient"] and first["status"] == "PENDING",
            f"{first['approvals_counted']}/{first['required_approvals']} approvals",
        )
        consumed_early = False
        try:
            approval_service.consume(session, approval_id=approval["approval_id"], acting_role="RECIPIENT")
        except ApprovalRequired:
            consumed_early = True
        check("action cannot proceed on one approval", consumed_early)

        second = approval_service.request(
            session,
            action="EVIDENCE_EXPORT",
            requested_by="COMMANDER-001",
            justification="Second synthetic two-person control demonstration",
            subject_id=case.case_id,
        )
        approval_service.approve(
            session, approval_id=second["approval_id"], approver_id="SECURITY-001",
            approver_role="SECURITY_OFFICER",
        )
        self_approve_blocked = False
        try:
            approval_service.approve(
                session, approval_id=second["approval_id"], approver_id="COMMANDER-001",
                approver_role="COMMANDER",
            )
        except ForgeError:
            self_approve_blocked = True
        check("requester cannot approve their own request", self_approve_blocked)

        step(13, "Emergency lockdown blocks new decryptions but keeps evidence")
        lockdown.activate(
            session, actor_id="COMMANDER-001", reason="Synthetic demonstration of emergency lockdown"
        )
        lockdown_refused = False
        try:
            nonce_six = decryption_service.issue_nonce(
                session, recipient_id="RECIPIENT-001", document_id=document_id
            )
            decryption_service.decrypt(
                session,
                actor=recipient_one,
                document_id=document_id,
                device_id="DEV-RECIPIENT-001-A",
                nonce=nonce_six["nonce"],
            )
        except LockdownActive as exc:
            lockdown_refused = True
            print(f"  refused    : {type(exc).__name__} — {exc.plain_explanation}")
        check("EMERGENCY LOCKDOWN blocks new decryptions", lockdown_refused)
        break_glass = approval_service.request_break_glass(
            session,
            recipient_id="RECIPIENT-001",
            document_id=document_id,
            reason="Synthetic emergency operational requirement for demonstration",
        )
        approval_service.approve(
            session, approval_id=break_glass["approval_id"], approver_id="SECURITY-001",
            approver_role="SECURITY_OFFICER",
        )
        break_glass_satisfied = approval_service.approve(
            session, approval_id=break_glass["approval_id"], approver_id="COMMANDER-001",
            approver_role="COMMANDER",
        )["sufficient"]
        check("break-glass needs two distinct approvers", break_glass_satisfied)
        nonce_seven = decryption_service.issue_nonce(
            session, recipient_id="RECIPIENT-001", document_id=document_id
        )
        emergency = decryption_service.decrypt(
            session,
            actor=recipient_one,
            document_id=document_id,
            device_id="DEV-RECIPIENT-001-A",
            nonce=nonce_seven["nonce"],
            break_glass_approval_id=break_glass["approval_id"],
        )
        check(
            "two-person-approved emergency access succeeds and is recorded",
            emergency["break_glass"],
            emergency["session_id"],
        )
        lockdown.release(session, actor_id="COMMANDER-001", reason="Synthetic lockdown lifted")
        check("lockdown released, evidence intact", not lockdown.is_active(session))

        step(14, "Offline operation: queue events, then synchronise")
        # Two of three nodes unreachable: below quorum, so the signed event must
        # be queued locally rather than committed or dropped.
        NETWORK.partition(["NODE-B", "NODE-C"])
        nonce_eight = decryption_service.issue_nonce(
            session, recipient_id="RECIPIENT-001", document_id=document_id
        )
        offline_session = decryption_service.decrypt(
            session,
            actor=recipient_one,
            document_id=document_id,
            device_id="DEV-RECIPIENT-001-A",
            nonce=nonce_eight["nonce"],
            offline=True,
        )
        offline_ledger = offline_session["ledger"]
        print(f"  ledger     : {offline_ledger['status']} — {offline_ledger['plain_explanation']}")
        check("offline decryption still permitted by policy", bool(offline_session["session_id"]))
        check("event queued rather than dropped", offline_ledger["status"] in ("COMMITTED", "QUEUED_OFFLINE"))
        NETWORK.heal()
        sync = NETWORK.sync()
        print(f"  sync       : {sync['status']} — pending after sync {sync['pending_after_sync']}")
        check("no offline event lost", sync["pending_after_sync"] == 0)

        step(15, "Ledger integrity, Merkle proof and event chain")
        verification = NETWORK.verify()
        print(f"  {verification['headline']}")
        for node in verification["nodes"]:
            print(f"    {node['node_id']:<8} {node['status']:<16} height {node['block_height']} "
                  f"txs {node['transactions_checked']}")
        check("multi-node ledger verifies", verification["headline"].endswith("VERIFIED"))
        check("all nodes agree on history", verification["agreement"]["status"] == "CONSISTENT")
        proof = NETWORK.prove_transaction(session_one["ledger"]["tx_id"])
        print(f"  merkle     : {proof['status']} (index {proof['proof']['index']})")
        check("Merkle inclusion proof verifies", proof["verified"])
        chain = decryption_service.verify_event_chain(session)
        print(f"  events     : {chain['events']} chained — {chain['status']}")
        check("signed event chain verifies", chain["status"] == "VERIFIED")

        step(16, "Ledger tampering is detected and reported, never overwritten")
        tamper = ATTACK_SCENARIOS["ledger_tampering"](session)
        print(f"  result     : {tamper['outcome']}")
        print(f"  guard      : storage immutability guard refused the first write = "
              f"{tamper['storage_guard_refused_first_write']}")
        for node in tamper["verification"]["nodes"]:
            print(f"    {node['node_id']:<8} {node['status']:<16} {[f['check'] for f in node['failures']]}")
        check("LEDGER TAMPER DETECTED", "TAMPER DETECTED" in tamper["outcome"])

        step(17, "Service key cannot forge a recipient's attribution")
        forgery = ATTACK_SCENARIOS["signature_forgery"](session)
        print(f"  result     : {forgery['outcome']} — signed by {forgery['signed_by']}, "
              f"claimed for {forgery['claimed_recipient_id']}")
        check("service key cannot forge recipient attribution", forgery["verdict"] == "SIGNATURE INVALID")

        step(18, "Remaining attack simulations")
        for name in ("replay_attack", "unknown_device", "revoked_user", "document_modification",
                     "watermark_corruption", "node_failure", "network_partition"):
            outcome = ATTACK_SCENARIOS[name](session)
            print(f"  {name:<24} {outcome['detected_as']:<38} {outcome['outcome']}")
            check(f"attack detected: {name}", outcome["detected"])

        step(19, "Security posture and command summary")
        from app.services import command_service

        posture = command_service.security_posture(session)
        print(f"  posture    : {posture['score']}/100 — {posture['rating']}")
        for factor in posture["factors"]:
            print(f"    {factor['factor']:<26} {factor['value']:>4}  {factor['detail']}")
        check("posture computed from measurable factors", 0 <= posture["score"] <= 100)

        step(20, "Watermark robustness measured, not asserted")
        from app.services import watermark_service

        original = Path(document_service.current_version(session, document_id).normalized_pdf_path)
        robustness = watermark_service.robustness_report(original)
        for entry in robustness["results"]:
            print(f"  {entry['transformation']:<24} recovered={str(entry['recovered']):<6} "
                  f"cnr={entry['carrier_to_noise_ratio']}")
        recovered = robustness["transformations_recovered"]
        check(
            "watermark survives re-save, compression and rescale",
            recovered >= 3,
            f"{recovered}/{robustness['transformations_tested']}",
        )

        step(21, "Audit chain integrity")
        from app.services import audit_service

        audit = audit_service.verify_chain(session)
        print(f"  audit      : {audit['chain_length']} records — {audit['status']}")
        check("privileged-action audit chain verifies", audit["status"] == "VERIFIED")

    print("\n" + "=" * 78)
    if failures:
        print(f"RESULT: {len(failures)} CHECK(S) FAILED")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("RESULT: ALL CHECKS PASSED")
    print(
        "\nATTRIBUTION STATEMENT: the system established a cryptographically verifiable\n"
        "association between the submitted copy and an authorised decryption session.\n"
        "It does not prove that any individual physically released the material."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
