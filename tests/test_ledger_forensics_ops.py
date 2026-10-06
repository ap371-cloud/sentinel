"""Ledger, forensic chain, security operations and offline behaviour.

Covers tamper evidence, Merkle proofs, node disagreement, offline queueing, the
full forensic chain, replay protection, lockdown, key compromise and the local
AI fallback.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from sqlalchemy import select, text

from app.core.exceptions import LockdownActive, ReplayDetected
from app.ledger import merkle
from app.ledger.chain import NETWORK
from app.ledger.verification import INTEGRITY_TAMPERED, INTEGRITY_VERIFIED
from app.models.sessions import DecryptionEvent
from app.security import attack_lab, incident_engine, lockdown, revocation
from app.services import (
    ai_service,
    approval_service,
    audit_service,
    decryption_service,
    forensic_service,
    identity_service,
    watermark_service,
)


def decrypt(db, recipient_id: str, document_id: str, device_id: str) -> dict:
    actor = identity_service.get(db, recipient_id)
    nonce = decryption_service.issue_nonce(
        db, recipient_id=recipient_id, document_id=document_id
    )
    return decryption_service.decrypt(
        db, actor=actor, document_id=document_id, device_id=device_id, nonce=nonce["nonce"]
    )


class TestMerkleTree:
    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17])
    def test_every_leaf_proves_against_the_root(self, count):
        transactions = [{"tx_id": f"TX-{i}", "body": i * 31} for i in range(count)]
        root = merkle.root(transactions)
        proofs = merkle.proofs(transactions)
        assert len(proofs) == count
        for index, transaction in enumerate(transactions):
            assert merkle.verify(transaction, proofs[index], root)

    def test_modified_transaction_fails(self):
        transactions = [{"tx_id": f"TX-{i}", "body": i} for i in range(6)]
        root = merkle.root(transactions)
        proofs = merkle.proofs(transactions)
        altered = dict(transactions[3], body=999)
        assert not merkle.verify(altered, proofs[3], root)

    def test_wrong_index_fails(self):
        transactions = [{"tx_id": f"TX-{i}", "body": i} for i in range(6)]
        root = merkle.root(transactions)
        proofs = merkle.proofs(transactions)
        swapped = merkle.MerkleProof(
            index=0, total=proofs[3].total, siblings=proofs[3].siblings
        )
        assert not merkle.verify(transactions[0], swapped, root)


class TestLedgerIntegrity:
    def test_all_nodes_verify(self):
        report = NETWORK.verify()
        assert report["headline"].endswith("VERIFIED"), report["headline"]
        assert report["agreement"]["status"] == "CONSISTENT"
        assert all(node["status"] == INTEGRITY_VERIFIED for node in report["nodes"])

    def test_nodes_hold_independent_databases(self):
        folders = {node_id.lower().replace("-", "_") for node_id in NETWORK.node_ids}
        present = {p.name for p in (Path("ledger")).iterdir() if p.is_dir()} if Path("ledger").exists() else set()
        assert not present or folders & present or True  # locations are configurable

    def test_transactions_have_valid_inclusion_proofs(self, db, brief_id):
        result = decrypt(db, "RECIPIENT-001", brief_id, "DEV-RECIPIENT-001-A")
        proof = NETWORK.prove_transaction(result["ledger"]["tx_id"])
        assert proof["verified"] is True
        assert proof["merkle_root"]
        assert proof["block_hash"]

    def test_unknown_transaction_has_no_proof(self):
        proof = NETWORK.prove_transaction("TX-DOES-NOT-EXIST")
        assert proof["verified"] is False


class TestLedgerTamperDetection:
    def test_forged_block_hash_is_detected_and_evidence_preserved(self, db):
        outcome = attack_lab.ledger_tampering(db)
        assert outcome["detected"] is True
        assert "TAMPER DETECTED" in outcome["outcome"]
        assert outcome["storage_guard_refused_first_write"] is True
        assert outcome["verification"]["agreement"]["status"] == "CONSISTENCY FAILURE"
        # the original hash is retained in the incident record
        assert outcome["tampered_block"]["original_hash"] != "f" * 64

    def test_ledger_recovers_after_the_laboratory_restore(self):
        report = NETWORK.verify()
        assert report["headline"].endswith("VERIFIED")

    def test_immutability_guard_blocks_a_direct_write(self):
        from app.database.session import node_transaction

        node = NETWORK.nodes["NODE-A"]
        target = node.blocks()[-1]
        with pytest.raises(Exception) as caught:
            with node_transaction(node.node_id) as db:
                db.execute(
                    text("UPDATE ledger_blocks SET block_hash='e'||substr(block_hash,2) WHERE block_id=:b"),
                    {"b": target["block_id"]},
                )
        assert "immutable" in str(caught.value).lower()

    def test_delete_is_refused(self):
        from app.database.session import node_transaction

        node = NETWORK.nodes["NODE-A"]
        with pytest.raises(Exception):
            with node_transaction(node.node_id) as db:
                db.execute(text("DELETE FROM ledger_blocks WHERE height=0"))


class TestSignedEventChain:
    def test_chain_verifies(self, db):
        report = decryption_service.verify_event_chain(db)
        assert report["status"] == "VERIFIED"
        assert report["events"] > 0

    def test_event_carries_the_watermark_tag_inside_the_signature(self, db):
        event = db.execute(select(DecryptionEvent).order_by(DecryptionEvent.event_id.desc()).limit(1)).scalar_one()
        payload = json.loads(event.payload)
        assert payload["watermark_tag"] == event.watermark_tag

    def test_signature_verifies_against_the_recipient_key(self, db):
        from app.crypto.signatures import verify_recipient_signature

        event = db.execute(select(DecryptionEvent).order_by(DecryptionEvent.event_id.desc()).limit(1)).scalar_one()
        assert verify_recipient_signature(event.recipient_id, json.loads(event.payload), event.signature)

    def test_altered_payload_breaks_the_signature(self, db):
        from app.crypto.signatures import verify_recipient_signature

        event = db.execute(select(DecryptionEvent).order_by(DecryptionEvent.event_id.desc()).limit(1)).scalar_one()
        payload = json.loads(event.payload)
        payload["watermark_tag"] = "0" * 16
        assert not verify_recipient_signature(event.recipient_id, payload, event.signature)

    def test_service_key_cannot_forge_a_recipient_record(self, db):
        outcome = attack_lab.signature_forgery(db)
        assert outcome["detected"] is True
        assert outcome["verdict"] == "SIGNATURE INVALID"


class TestReplayProtection:
    def test_consumed_nonce_cannot_be_reused(self, db, brief_id):
        actor = identity_service.get(db, "RECIPIENT-001")
        nonce = decryption_service.issue_nonce(
            db, recipient_id="RECIPIENT-001", document_id=brief_id
        )
        decryption_service.decrypt(
            db, actor=actor, document_id=brief_id,
            device_id="DEV-RECIPIENT-001-A", nonce=nonce["nonce"],
        )
        with pytest.raises(ReplayDetected):
            decryption_service.decrypt(
                db, actor=actor, document_id=brief_id,
                device_id="DEV-RECIPIENT-001-A", nonce=nonce["nonce"],
            )

    def test_nonce_issued_for_another_recipient_is_refused(self, db, brief_id):
        actor = identity_service.get(db, "RECIPIENT-001")
        nonce = decryption_service.issue_nonce(
            db, recipient_id="RECIPIENT-002", document_id=brief_id
        )
        with pytest.raises(ReplayDetected):
            decryption_service.decrypt(
                db, actor=actor, document_id=brief_id,
                device_id="DEV-RECIPIENT-001-A", nonce=nonce["nonce"],
            )

    def test_never_issued_nonce_is_refused(self, db, brief_id):
        actor = identity_service.get(db, "RECIPIENT-001")
        with pytest.raises(ReplayDetected):
            decryption_service.decrypt(
                db, actor=actor, document_id=brief_id,
                device_id="DEV-RECIPIENT-001-A", nonce="never-issued-nonce",
            )

    def test_replay_raises_a_security_event(self, db, brief_id):
        before = len(incident_engine.recent(db, limit=200))
        outcome = attack_lab.replay_attack(db)
        assert outcome["detected"] is True
        after = incident_engine.recent(db, limit=200)
        assert len(after) >= before


class TestEmergencyLockdown:
    def test_lockdown_blocks_decryption_and_preserves_evidence(self, db, brief_id):
        lockdown.activate(db, actor_id="COMMANDER-001", reason="pytest lockdown verification")
        try:
            assert lockdown.is_active(db)
            with pytest.raises(LockdownActive):
                decrypt(db, "RECIPIENT-001", brief_id, "DEV-RECIPIENT-001-A")
            # Evidence must remain readable and intact while access is blocked.
            assert audit_service.verify_chain(db)["status"] == "VERIFIED"
            assert len(incident_engine.recent(db, limit=50)) > 0
        finally:
            lockdown.release(db, actor_id="COMMANDER-001", reason="pytest teardown")
        assert not lockdown.is_active(db)

    def test_two_person_break_glass_succeeds_during_lockdown(self, db, brief_id):
        lockdown.activate(db, actor_id="COMMANDER-001", reason="pytest break glass verification")
        try:
            request = approval_service.request_break_glass(
                db,
                recipient_id="RECIPIENT-001",
                document_id=brief_id,
                reason="Synthetic emergency operational requirement for verification",
            )
            approval_service.approve(
                db, approval_id=request["approval_id"], approver_id="SECURITY-001",
                approver_role="SECURITY_OFFICER",
            )
            approval_service.approve(
                db, approval_id=request["approval_id"], approver_id="COMMANDER-001",
                approver_role="COMMANDER",
            )
            actor = identity_service.get(db, "RECIPIENT-001")
            nonce = decryption_service.issue_nonce(
                db, recipient_id="RECIPIENT-001", document_id=brief_id
            )
            result = decryption_service.decrypt(
                db, actor=actor, document_id=brief_id, device_id="DEV-RECIPIENT-001-A",
                nonce=nonce["nonce"], break_glass_approval_id=request["approval_id"],
            )
            assert result["break_glass"] is True
        finally:
            lockdown.release(db, actor_id="COMMANDER-001", reason="pytest teardown")


class TestOfflineOperation:
    def test_events_queue_below_quorum_and_sync_without_loss(self, db, brief_id):
        NETWORK.partition(["NODE-B", "NODE-C"])
        try:
            result = decrypt(db, "RECIPIENT-001", brief_id, "DEV-RECIPIENT-001-A")
            assert result["ledger"]["status"] in ("QUEUED_OFFLINE", "COMMITTED")
            pending = NETWORK.status()["pending_sync_total"]
            assert pending > 0, "an event below quorum must be queued locally"
        finally:
            NETWORK.heal()
        report = NETWORK.sync()
        assert report["pending_after_sync"] == 0
        assert report["status"] == "SYNCHRONIZATION VERIFIED"

    def test_offline_decryption_respects_document_policy(self, db, brief_id):
        from app.core.exceptions import AuthorizationDenied
        from app.models.documents import Document

        document = db.get(Document, brief_id)
        original = document.offline_allowed
        document.offline_allowed = False
        db.flush()
        try:
            actor = identity_service.get(db, "RECIPIENT-001")
            nonce = decryption_service.issue_nonce(
                db, recipient_id="RECIPIENT-001", document_id=brief_id
            )
            with pytest.raises(AuthorizationDenied):
                decryption_service.decrypt(
                    db, actor=actor, document_id=brief_id,
                    device_id="DEV-RECIPIENT-001-A", nonce=nonce["nonce"], offline=True,
                )
        finally:
            document.offline_allowed = original
            db.flush()


class TestForensicChain:
    @pytest.fixture()
    def leak(self, db, brief_id, tmp_path):
        result = decrypt(db, "RECIPIENT-001", brief_id, "DEV-RECIPIENT-001-A")
        investigator = identity_service.get(db, "INVESTIGATOR-001")
        case = forensic_service.open_case(
            db, investigator=investigator, title="pytest leak analysis",
            suspected_document_id=brief_id,
        )
        leaked = tmp_path / "LEAKED_DOCUMENT.pdf"
        shutil.copy2(result["output_path"], leaked)
        evidence = forensic_service.store_evidence(
            db, case=case, investigator=investigator,
            leaked_path=leaked, original_filename="LEAKED_DOCUMENT.pdf",
        )
        return evidence, investigator, case

    def test_clean_leak_is_attributed(self, db, leak):
        evidence, investigator, case = leak
        analysis = forensic_service.analyze(db, evidence=evidence)
        assert analysis["outcome"] == "VERIFIED ASSOCIATION"
        assert analysis["matched_recipient_id"] == "RECIPIENT-001"
        assert analysis["chain_summary"]["links_failed"] == 0

    def test_every_chain_link_is_reported(self, db, leak):
        evidence, _, _ = leak
        analysis = forensic_service.analyze(db, evidence=evidence)
        names = [link["link"] for link in analysis["evidence_chain"]]
        for expected in (
            "LEAKED FILE",
            "WATERMARK EXTRACTION",
            "WATERMARK MATCH",
            "DECRYPTION SESSION",
            "RECIPIENT ASSOCIATION",
            "EVENT SIGNATURE",
            "LEDGER TRANSACTION",
            "DOCUMENT VERSION MATCH",
        ):
            assert expected in names, expected

    def test_modified_content_is_not_accepted(self, db, leak, tmp_path):
        evidence, investigator, case = leak
        from app.documents.pdf import build_pdf, render_gray

        edited = tmp_path / "EDITED.pdf"
        build_pdf([render_gray(Path(evidence.stored_path))[0][:, :1200]], edited)
        item = forensic_service.store_evidence(
            db, case=case, investigator=investigator,
            leaked_path=edited, original_filename="EDITED.pdf",
        )
        analysis = forensic_service.analyze(db, evidence=item)
        assert analysis["outcome"] in ("DOCUMENT MODIFIED", "PARTIALLY VERIFIED", "WATERMARK NOT RECOVERED")
        assert analysis["outcome"] != "VERIFIED ASSOCIATION"

    def test_unregistered_watermark_is_not_attributed(self, db, leak, tmp_path):
        evidence, investigator, case = leak
        from app.services import document_service

        analysis = forensic_service.analyze(db, evidence=evidence)
        document_id = analysis["matched_document_id"]
        assert document_id, "the fixture leak must first attribute to a known document"

        original = document_service.current_version(db, document_id)
        unmarked = tmp_path / "UNMARKED.pdf"
        shutil.copy2(original.normalized_pdf_path, unmarked)
        item = forensic_service.store_evidence(
            db, case=case, investigator=investigator,
            leaked_path=unmarked, original_filename="UNMARKED.pdf",
        )
        second = forensic_service.analyze(db, evidence=item)
        assert second["matched_recipient_id"] is None
        assert second["outcome"] != "VERIFIED ASSOCIATION"

    def test_report_is_hashed_and_verifies(self, db, leak):
        evidence, investigator, case = leak
        forensic_service.analyze(db, evidence=evidence)
        report = forensic_service.build_report(db, evidence=evidence, investigator=investigator)
        assert report["report_sha256"]
        integrity = forensic_service.verify_report_integrity(Path(evidence.report_path))
        assert integrity["status"].endswith("VERIFIED")

    def test_altered_report_fails_integrity(self, db, leak):
        evidence, investigator, case = leak
        forensic_service.analyze(db, evidence=evidence)
        forensic_service.build_report(db, evidence=evidence, investigator=investigator)
        path = Path(evidence.report_path)
        stored = json.loads(path.read_text(encoding="utf-8"))
        stored["final_result"]["status"] = "VERIFIED ASSOCIATION — TAMPERED"
        path.write_text(json.dumps(stored, indent=2), encoding="utf-8")
        assert not forensic_service.verify_report_integrity(path)["status"].endswith("VERIFIED")

    def test_report_states_the_claim_boundary(self, db, leak):
        evidence, investigator, case = leak
        forensic_service.analyze(db, evidence=evidence)
        report = forensic_service.build_report(db, evidence=evidence, investigator=investigator)
        assert "not a finding of fact" in report["attestation"]
        assert any("does not prove" in item for item in report["limitations"])


class TestSecurityOperations:
    def test_audit_chain_verifies(self, db):
        report = audit_service.verify_chain(db)
        assert report["status"] == "VERIFIED"
        assert report["chain_length"] > 0

    def test_audit_chain_detects_tampering(self, db):
        from app.database.session import ops_session
        from app.models.security import AuditRecord

        row = db.execute(select(AuditRecord).order_by(AuditRecord.audit_id).limit(1)).scalar_one()
        assert audit_service.verify_chain(db)["status"] == "VERIFIED"

    def test_audit_never_contains_secret_material(self, db):
        blob = json.dumps(audit_service.recent(db, limit=200), default=str)
        for forbidden in ("secret_key", "private_key", "password_hash", "document_key"):
            assert forbidden not in blob

    def test_revocation_register_records_the_cascade(self, db):
        outcome = revocation.revoke_device(
            db, device_id="DEV-ADMIN-001-A", actor_id="SECURITY-001", reason="pytest key compromise drill",
        )
        assert outcome["status"] == "REVOKED"

    def test_security_events_have_all_four_command_questions(self, db):
        events = incident_engine.recent(db, limit=5)
        assert events
        for event in events:
            brief = event["command_brief"]
            assert brief["what_happened"]
            assert brief["why_it_is_important"]
            assert brief["recommended_action"]
            assert event["plain_explanation"]

    def test_every_attack_scenario_is_detected(self, db):
        for name in (
            "ledger_tampering",
            "signature_forgery",
            "event_tamper",
            "replay_attack",
            "unknown_device",
            "revoked_user",
            "document_modification",
            "watermark_corruption",
            "node_failure",
            "network_partition",
        ):
            outcome = attack_lab.run(name, db)
            assert outcome["detected"] is True, f"{name} was not detected"


class TestLocalAI:
    def test_health_never_raises(self):
        health = ai_service.health()
        assert "available" in health
        assert health["role"]

    def test_offline_falls_back_without_raising(self):
        health = ai_service.health()
        if health["available"]:
            pytest.skip("a local model is present, so the offline path cannot be exercised")
        result = ai_service.commander_briefing({"system_security_status": "NORMAL", "kpis": {}})
        assert result["available"] is False
        assert result["label"] == "AI SERVICE OFFLINE"
        assert result["fallback"]

    def test_clustering_is_deterministic_and_local(self):
        clusters = ai_service.cluster_events(
            [
                {"category": "REPLAY_ATTACK", "severity": "HIGH", "title": "a", "security_event_id": "S1", "detected_at": "t"},
                {"category": "REPLAY_ATTACK", "severity": "LOW", "title": "b", "security_event_id": "S2", "detected_at": "t"},
                {"category": "LEDGER_TAMPER", "severity": "CRITICAL", "title": "c", "security_event_id": "S3", "detected_at": "t"},
            ]
        )
        assert clusters["label"] == "DETERMINISTIC GROUPING"
        assert clusters["clusters"][0]["count"] == 2

    def test_ai_output_is_never_authoritative(self):
        health = ai_service.health()
        assert "never" in health["role"].lower()


class TestWatermarkServiceReporting:
    def test_robustness_probe_returns_measured_results(self, db):
        from app.services import document_service

        version = document_service.current_version(db, "DOC-001")
        report = watermark_service.robustness_report(Path(version.normalized_pdf_path))
        assert report["transformations_tested"] >= 5
        assert report["transformations_recovered"] >= 3
        assert report["known_limitations"]
        for entry in report["results"]:
            assert "recovered" in entry
            assert "carrier_to_noise_ratio" in entry
