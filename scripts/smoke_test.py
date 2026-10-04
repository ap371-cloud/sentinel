"""Imports every module and runs a functional smoke test of the layers that
have no HTTP dependency. Run this after each build step so a broken import or a
regression surfaces immediately instead of at demo time."""

from __future__ import annotations

import shutil
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

MODULES = [
    "app.core.config",
    "app.core.exceptions",
    "app.core.identifiers",
    "app.core.security",
    "app.core.permissions",
    "app.crypto.hashing",
    "app.crypto.pqc",
    "app.crypto.key_management",
    "app.crypto.signatures",
    "app.documents.pdf",
    "app.documents.encryption",
    "app.watermark.generator",
    "app.watermark.error_correction",
    "app.watermark.embedder",
    "app.watermark.extractor",
    "app.watermark.validation",
    "app.ledger.merkle",
    "app.ledger.block",
    "app.ledger.node",
    "app.ledger.verification",
    "app.ledger.chain",
    "app.security.incident_engine",
    "app.security.anomaly_detection",
    "app.security.lockdown",
    "app.security.revocation",
    "app.services.audit_service",
    "app.services.identity_service",
    "app.services.approval_service",
    "app.services.watermark_service",
    "app.services.document_service",
    "app.services.decryption_service",
    "app.services.forensic_service",
]


def import_all() -> list[str]:
    import importlib

    failures: list[str] = []
    for name in MODULES:
        try:
            importlib.import_module(name)
        except Exception:
            failures.append(name)
            print(f"IMPORT FAIL  {name}")
            print(traceback.format_exc())
    return failures


def reset_state() -> None:
    """Development databases and generated artefacts are disposable. Evidence
    and ledger files are cleared too so a smoke test never reports history it
    inherited from a previous run."""
    for target in (ROOT / "data", ROOT / "ledger", ROOT / "evidence", ROOT / "keys"):
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
    for folder in ("data", "ledger", "evidence", "keys"):
        (ROOT / folder).mkdir(parents=True, exist_ok=True)


def check_merkle() -> None:
    from app.ledger import merkle

    # Every leaf count from 1..17, because odd levels are padded and that padding
    # is where proof construction usually goes wrong.
    for count in range(1, 18):
        transactions = [{"tx_id": f"TX-{i}", "value": i * 7} for i in range(count)]
        root = merkle.root(transactions)
        proofs = merkle.proofs(transactions)
        assert len(proofs) == count, f"expected {count} proofs, got {len(proofs)}"
        for index, tx in enumerate(transactions):
            assert merkle.verify(tx, proofs[index], root), f"count={count} index={index} failed to verify"
        tampered = dict(transactions[count // 2])
        tampered["value"] = 999999
        assert not merkle.verify(tampered, proofs[count // 2], root), "tampered transaction verified"
        foreign_root = ("f" if root[0] != "f" else "0") + root[1:]
        assert not merkle.verify(transactions[0], proofs[0], foreign_root), "verified against a foreign root"


def check_pqc() -> None:
    from app.crypto.pqc import CTX_DECRYPTION_EVENT, PQC

    keys = PQC.generate_signing_keypair()
    signature = PQC.sign(keys.secret_key, b"sentinel-smoke", context=CTX_DECRYPTION_EVENT)
    assert PQC.verify(keys.public_key, b"sentinel-smoke", signature.raw, context=CTX_DECRYPTION_EVENT)
    assert not PQC.verify(keys.public_key, b"sentinel-smokf", signature.raw, context=CTX_DECRYPTION_EVENT)


def check_watermark() -> None:
    import pymupdf

    from app.core.config import PATHS
    from app.watermark.embedder import embed
    from app.watermark.extractor import extract
    from app.watermark.generator import derive_tag, derivation_inputs

    root_secret = b"sentinel-smoke-root-secret-value"
    source = PATHS.render / "smoke.pdf"
    document = pymupdf.open()
    page = document.new_page(width=595, height=842)
    page.insert_textbox(pymupdf.Rect(56, 56, 540, 780), "SENTINEL SMOKE TEST\n" + "line\n" * 200, fontsize=10)
    document.save(source)
    document.close()

    document_id, document_hash, version_id = "DOC-SMOKE", "a" * 64, "VER-SMOKE"
    tag = derive_tag(
        root_secret,
        derivation_inputs(
            recipient_id="REC-SMOKE",
            document_id=document_id,
            document_hash=document_hash,
            session_id="SES-SMOKE",
            nonce="b" * 32,
            watermark_version="WM-1.0",
            policy_version="POL-1.0",
        ),
    )
    marked = PATHS.render / "smoke_marked.pdf"
    result = embed(
        source, marked, root_secret=root_secret, document_id=document_id,
        document_hash=document_hash, version_id=version_id, tag_hex=tag,
    )
    assert result.psnr_db > 33, f"PSNR too low: {result.psnr_db}"
    assert result.ssim_score > 0.95, f"SSIM too low: {result.ssim_score}"
    found = extract(
        marked, root_secret=root_secret, document_id=document_id,
        document_hash=document_hash, version_id=version_id,
    ).best
    assert found is not None and found.recovered_tag == tag, "watermark round trip failed"


def check_ledger() -> None:
    from app.database.session import create_node_schema, create_ops_schema
    from app.ledger.block import Transaction
    from app.ledger.chain import NETWORK

    create_ops_schema()
    for node_id in NETWORK.node_ids:
        create_node_schema(node_id)
    NETWORK.ensure_ready()
    assert NETWORK.verify()["headline"].endswith("VERIFIED"), "fresh network did not verify"

    transaction = Transaction(
        tx_id="TX-SMOKE-1",
        event_id="EVT-SMOKE-1",
        event_hash="c" * 64,
        event_type="DOCUMENT_DECRYPTED",
        recipient_id="REC-SMOKE",
        document_id="DOC-SMOKE",
        version_id="VER-SMOKE",
        document_hash="a" * 64,
        watermark_tag="deadbeefdeadbeef",
        session_id="SES-SMOKE",
        payload={"event_id": "EVT-SMOKE-1"},
        recipient_signature="",
        signature_algorithm="Mldsa65",
        signing_key_id="REC-SMOKE-SIG-Mldsa65",
    )
    outcome = NETWORK.submit(transaction)
    assert outcome["committed"], outcome
    proof = NETWORK.prove_transaction("TX-SMOKE-1")
    assert proof["verified"], proof
    after = NETWORK.verify()
    assert after["headline"].endswith("VERIFIED"), after["headline"]


def main() -> int:
    reset_state()
    failures = import_all()
    if failures:
        print(f"\nIMPORT FAILURES: {failures}")
        return 1

    checks = (
        ("merkle", check_merkle),
        ("pqc", check_pqc),
        ("watermark", check_watermark),
        ("ledger", check_ledger),
    )
    for name, check in checks:
        try:
            check()
            print(f"OK    {name}")
        except Exception:
            print(f"FAIL  {name}")
            print(traceback.format_exc())
            failures.append(name)

    print("\nSMOKE TEST:", "ALL GREEN" if not failures else f"{len(failures)} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
