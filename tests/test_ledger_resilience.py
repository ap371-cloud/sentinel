"""Ledger resilience visibility (Phase 21).

Every node reports as an ONLINE/OFFLINE + HEIGHT line, and mismatches surface
as LEDGER CONSISTENCY FAILURE with the conflicting block, its hashes and the
affected nodes — never a silent in-place repair.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tests.conftest import decrypt_once, headers

from app.database.session import node_transaction
from app.ledger.chain import NETWORK
from app.security.attack_lab import _drop_immutability_guards, _install_immutability_guards, _restore_block_hash
from sqlalchemy import text


def live_view(client, tokens) -> dict:
    body = client.get("/ledger/resilience", headers=headers(tokens["ledger"])).json()
    assert body["ledger_consistency"]
    return body


class TestResilienceView:
    def test_healthy_view_lists_every_node_with_height(self, db, client, tokens, brief_id):
        decrypt_once(db, recipient_id="RECIPIENT-001", document_id=brief_id, device_id="DEV-RECIPIENT-001-A")
        view = live_view(client, tokens)
        lines = {line["node_id"]: line for line in view["nodes"]}
        assert lines["NODE-A"]["status"] == "ONLINE" and lines["NODE-B"]["status"] == "ONLINE"
        assert lines["NODE-C"]["status"] == "ONLINE"
        assert all(line["block_height"] >= 1 for line in lines.values())
        assert all(line["integrity_status"] == "VERIFIED" for line in lines.values())
        assert view["ledger_consistency"] == "CONSISTENT"
        assert view["conflicting_blocks"] == []
        assert view["affected_nodes"] == []
        assert view["verification_state"]["agreement_status"] == "CONSISTENT"
        assert view["never_overwritten_note"]

    def test_offline_node_keeps_its_height_and_is_reported_not_erased(self, db, client, tokens, brief_id):
        decrypt_once(db, recipient_id="RECIPIENT-001", document_id=brief_id, device_id="DEV-RECIPIENT-001-A")
        before = {line["node_id"]: line["block_height"] for line in NETWORK.status()["nodes"]}
        try:
            NETWORK.partition(["NODE-C"])
            view = live_view(client, tokens)
            lines = {line["node_id"]: line for line in view["nodes"]}
            assert lines["NODE-C"]["status"] == "OFFLINE"
            # the offline copy is not blanked: its height is still reported
            assert lines["NODE-C"]["block_height"] == before["NODE-C"]
            # quorum is intact, so this is replication lag, not a consistency failure
            assert view["ledger_consistency"] == "CONSISTENT"
            assert view["offline_nodes"] == ["NODE-C"]
            assert "NODE-C" in view["affected_nodes"]
            assert lines["NODE-A"]["block_height"] == lines["NODE-B"]["block_height"]
        finally:
            NETWORK.heal()
        after = live_view(client, tokens)
        assert after["offline_nodes"] == []
        assert after["ledger_consistency"] == "CONSISTENT"

    def test_tampered_node_flags_consistency_failure_with_conflicting_block(self, db, client, tokens, brief_id):
        decrypt_once(db, recipient_id="RECIPIENT-001", document_id=brief_id, device_id="DEV-RECIPIENT-001-A")
        victim = NETWORK.nodes["NODE-A"]
        target = victim.blocks()[-1]
        original_hash = target["block_hash"]
        forged = "f" * 64
        try:
            _drop_immutability_guards("NODE-A")
            with node_transaction("NODE-A") as node_db:
                node_db.execute(
                    text("UPDATE ledger_blocks SET block_hash = :forged WHERE block_id = :block_id"),
                    {"forged": forged, "block_id": target["block_id"]},
                )
            view = live_view(client, tokens)
            assert view["ledger_consistency"] == "LEDGER CONSISTENCY FAILURE"
            assert "INTEGRITY_TAMPER_DETECTED" in view["consistency_reasons"]
            lines = {line["node_id"]: line for line in view["nodes"]}
            assert lines["NODE-A"]["integrity_status"] == "TAMPER DETECTED"
            assert lines["NODE-A"]["first_failing_height"] == target["height"]

            conflicting = {block["node_id"]: block for block in view["conflicting_blocks"]}
            assert "NODE-A" in conflicting
            assert conflicting["NODE-A"]["block_id"] == target["block_id"]
            assert conflicting["NODE-A"]["block_hash"] == forged
            assert conflicting["NODE-A"]["height"] == target["height"]
            assert "NODE-A" in view["affected_nodes"]
            assert view["verification_state"]["divergent_nodes"] and "NODE-A" in view["verification_state"]["divergent_nodes"]
            assert view["expected_head"]["block_hash"] != forged
            # nothing was repaired in place: the node still stores the forged copy
            assert victim.block_at(target["height"])["block_hash"] == forged
        finally:
            _restore_block_hash("NODE-A", target["block_id"], original_hash)
            _install_immutability_guards("NODE-A")

    def test_consistency_returns_after_restore(self, client, tokens):
        view = live_view(client, tokens)
        assert view["ledger_consistency"] == "CONSISTENT"
        assert all(line["integrity_status"] != "TAMPER DETECTED" for line in view["nodes"])

    def test_view_is_read_only_for_auditor(self, client, tokens):
        assert client.get("/ledger/resilience", headers=headers(tokens["auditor"])).status_code == 200