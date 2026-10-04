import json, shutil, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
for t in ("data", "ledger", "evidence", "keys"):
    shutil.rmtree(ROOT / t, ignore_errors=True); (ROOT / t).mkdir(parents=True, exist_ok=True)
from app.database.session import create_node_schema, create_ops_schema
create_ops_schema()
from app.ledger.chain import NETWORK
from app.ledger.block import Transaction
for n in NETWORK.node_ids: create_node_schema(n)
NETWORK.ensure_ready()
tx = Transaction(tx_id="TX-1", event_id="E1", event_hash="c"*64, event_type="DOCUMENT_DECRYPTED",
    recipient_id="REC-1", document_id="DOC-1", version_id="V1", document_hash="a"*64,
    watermark_tag="deadbeefdeadbeef", session_id="S1", payload={"event_id":"E1"},
    recipient_signature="", signature_algorithm="Mldsa65", signing_key_id="REC-1-SIG")
print(json.dumps(NETWORK.submit(tx), indent=1)[:400])
r = NETWORK.verify()
for n in r["nodes"]:
    print(n["node_id"], n["status"], [f["check"] for f in n["failures"]])
