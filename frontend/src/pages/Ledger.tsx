import { useMemo, useState } from "react";
import {
  api, endpoints,
  type Block, type LedgerNode, type LedgerStatus, type LedgerTx, type LedgerVerification,
} from "../api";
import {
  Badge, DataTable, Drawer, EmptyState, ErrorNotice, FilterChips, Hash, LoadingState,
  Metric, Modal, Notice, PageHead, Panel, Pipeline, SearchInput, StatusBadge,
  Unauthorized, VerificationStep, useAsync, useToast, type StepState,
} from "../components/ui";
import { IdentBadge, QuorumChip } from "../components/layout";

export function Ledger() {
  const toast = useToast();
  const status = useAsync<LedgerStatus>(() => api.get<LedgerStatus>(endpoints.ledgerStatus), []);
  const verify = useAsync<LedgerVerification>(() => api.get<LedgerVerification>(endpoints.ledgerVerify), []);
  const blocks = useAsync<{ blocks: Block[] }>(() => api.get(endpoints.ledgerBlocks), []);
  const [syncOpen, setSyncOpen] = useState(false);

  const nodes = status.data?.nodes ?? [];
  const canVerify = !verify.error;

  if (status.loading && !status.data) return <LoadingState label="Loading ledger status" detail="GET /ledger/status" />;
  if (status.error) {
    const st = (status.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={status.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={status.error} onRetry={status.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Ledger"
        sub="A permissioned append-only record of every protected action, replicated across three nodes. Tampering is detectable because each block commits to the one before it."
        actions={
          <>
            <QuorumChip nodes={nodes} quorumSize={status.data?.quorum_size ?? 2} />
            <button className="btn" onClick={() => { verify.reload(); status.reload(); blocks.reload(); }}>↻ Re-verify chain</button>
            <button className="btn primary" onClick={() => setSyncOpen(true)}>⇄ Synchronise nodes</button>
          </>
        }
      />

      <div className="grid g4">
        <Metric label="Block height" value={Math.max(0, ...nodes.map((n) => n.block_height))} tone="info"
          sub={`${status.data?.reachable_nodes ?? 0} of ${status.data?.node_count ?? nodes.length} replicas reachable`} />
        <Metric label="Quorum" value={`${status.data?.quorum_reachable ? "REACHED" : "AT RISK"}`}
          tone={status.data?.quorum_reachable ? "ok" : "crit"} sub={`quorum size ${status.data?.quorum_size ?? "—"}`} />
        <Metric label="Pending sync" value={status.data?.pending_sync_total ?? 0}
          tone={(status.data?.pending_sync_total ?? 0) > 0 ? "warn" : "ok"} sub="queued across replicas" />
        <Metric label="Verdict" small
          value={<StatusBadge status={verify.data?.headline ?? "NOT VERIFIED"} lg />}
          sub={verify.data ? `verified ${verify.data.verified_at}` : "run verification to populate"} />
      </div>

      <Panel title="Chain visualiser" actions={<Badge tone="info">NEWEST {Math.min(6, blocks.data?.blocks.length ?? 0)}</Badge>}>
        {blocks.loading && !blocks.data ? <LoadingState label="Loading blocks" /> : null}
        {blocks.error ? <ErrorNotice error={blocks.error} onRetry={blocks.reload} /> : null}
        <div className="chain-viz">
          {(blocks.data?.blocks ?? []).slice(0, 6).map((b) => (
            <div key={b.block_id} className={`chain-blk ${b.is_genesis ? "genesis" : ""}`}>
              <div className="h">{b.is_genesis ? "GENESIS" : `HEIGHT ${b.height}`}</div>
              <div className="id">#{b.height}</div>
              <div className="tiny dim">{b.transaction_count} tx · {b.proposer_id}</div>
              <div style={{ marginTop: 5 }}><Hash value={b.merkle_root} chars={12} copy={false} /></div>
            </div>
          ))}
        </div>
        <div className="tiny dim">
          Each block stores the Merkle root of its transactions and the hash of the previous block, so a rewritten
          history breaks every link after it.
        </div>
      </Panel>

      <div className="grid g-1-2">
        <Panel title="Node replicas" flush>
          <DataTable
            rows={nodes}
            empty={<EmptyState title="No nodes" sub="The ledger reported no replicas." />}
            columns={[
              { key: "n", head: "Node", render: (n) => <IdentBadge id={n.node_id} kind="node" /> },
              { key: "s", head: "Status", render: (n) => <StatusBadge status={n.status} /> },
              { key: "h", head: "Height", num: true, render: (n) => n.block_height },
              { key: "p", head: "Pending", num: true, render: (n) => n.pending_sync_count },
            ]}
          />
          {status.data?.plain_explanation ? (
            <div className="panel-body" style={{ borderTop: "1px solid var(--hair)" }}>
              <div className="tiny dim">{status.data.plain_explanation}</div>
            </div>
          ) : null}
        </Panel>

        <Panel title="Independent chain verification" actions={verify.loading ? <Badge tone="info">RUNNING</Badge> : null}>
          {verify.loading && !verify.data ? <LoadingState label="Verifying every block and Merkle proof" /> : null}
          {!canVerify && !verify.loading ? (
            <Unauthorized error={verify.error} onLogin={() => window.location.reload()} />
          ) : null}

          {verify.data ? (
            <>
              <Pipeline>
                {verify.data.nodes.map((n) => {
                  const state: StepState = n.first_failing_height !== null ? "fail"
                    : n.status === "HEALTHY" || n.status === "SYNCED" ? "pass" : "partial";
                  return (
                    <VerificationStep
                      key={n.node_id}
                      state={state}
                      name={n.node_id}
                      detail={`${n.blocks_checked} blocks and ${n.transactions_checked} transactions re-checked independently`}
                      right={<span className="mono tiny">h{n.block_height}</span>}
                    />
                  );
                })}
                <VerificationStep
                  state={verify.data.agreement.divergent.length ? "fail" : "pass"}
                  name="State-root agreement across replicas"
                  detail={verify.data.agreement.plain_explanation}
                  right={<Hash value={verify.data.agreement.state_root} chars={10} />}
                />
              </Pipeline>

              {verify.data.nodes.some((n) => n.failures.length) ? (
                <div className="mt">
                  <Notice tone="crit" title="Divergence reported">
                    <ul style={{ margin: "4px 0 0", paddingLeft: 16 }}>
                      {verify.data.nodes.flatMap((n) =>
                        n.failures.map((f) => (
                          <li key={`${n.node_id}-${f.height}-${f.check}`} className="tiny">
                            {n.node_id} · height {f.height} · {f.check}: {f.detail}
                          </li>
                        )))}
                    </ul>
                  </Notice>
                </div>
              ) : (
                <div className="mt">
                  <Notice tone="ok" title="No divergence detected">
                    Every replica agrees on the state root at height {verify.data.agreement.agreed_height}, and every
                    Merkle proof checked out.
                  </Notice>
                </div>
              )}
            </>
          ) : null}
        </Panel>
      </div>

      <LedgerExplorer />

      {syncOpen ? (
        <SyncModal
          nodes={nodes}
          onClose={() => setSyncOpen(false)}
          onDone={() => { status.reload(); blocks.reload(); verify.reload(); }}
        />
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------ tx explorer */

function LedgerExplorer() {
  const txs = useAsync<{ transactions: LedgerTx[] }>(() => api.get(endpoints.ledgerTransactions), []);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("all");
  const [openId, setOpenId] = useState<string | null>(null);

  const rows = txs.data?.transactions ?? [];
  const types = useMemo(() => ["all", ...new Set(rows.map((r) => r.event_type))], [rows]);
  const counts = useMemo(() => {
    const m: Record<string, number> = { all: rows.length };
    for (const t of types) m[t] = rows.filter((r) => r.event_type === t).length;
    return m;
  }, [rows, types]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (filter !== "all" && r.event_type !== filter) return false;
      if (!needle) return true;
      return [r.tx_id, r.event_type, r.recipient_id, r.document_id, r.session_id, r.committed_block_id ?? ""]
        .some((v) => v?.toLowerCase().includes(needle));
    });
  }, [rows, q, filter]);

  return (
    <Panel title="Transaction ledger" flush>
      <div className="panel-body" style={{ borderBottom: "1px solid var(--hair)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
        <SearchInput value={q} onChange={setQ} placeholder="Search transaction, event type, recipient, document, session…" width={380} />
        <FilterChips
          value={filter}
          onChange={setFilter}
          options={types.slice(0, 8).map((t) => ({ value: t, label: t.replace(/[._]/g, " ").toLowerCase(), count: counts[t] }))}
        />
        <span className="tiny dim" style={{ marginLeft: "auto" }}>{filtered.length} of {rows.length} shown</span>
      </div>

      {txs.loading && !txs.data ? <LoadingState label="Loading transactions" /> : null}
      {txs.error ? <ErrorNotice error={txs.error} onRetry={txs.reload} /> : null}
      {txs.data ? (
        <DataTable
          rows={filtered}
          onRow={(r) => setOpenId(r.tx_id)}
          empty={<EmptyState icon="⛓" title="No transactions match" sub="Nothing in the ledger matches these filters." />}
          columns={[
            { key: "e", head: "Event type", render: (r) => <Badge tone="info">{r.event_type.replace(/[._]/g, " ")}</Badge> },
            { key: "r", head: "Recipient", render: (r) => <span className="mono">{r.recipient_id}</span> },
            { key: "d", head: "Document", render: (r) => <IdentBadge id={r.document_id} /> },
            { key: "s", head: "Session", render: (r) => <IdentBadge id={r.session_id} kind="session" /> },
            { key: "b", head: "Block", render: (r) => <Hash value={r.committed_block_id} chars={14} /> },
            { key: "c", head: "Committed", render: (r) => <span className="tiny dim">{r.committed_at?.slice(0, 19).replace("T", " ")}</span> },
          ]}
        />
      ) : null}

      {openId ? <TxDrawer id={openId} onClose={() => setOpenId(null)} /> : null}
    </Panel>
  );
}

function TxDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const detail = useAsync<{ transaction: LedgerTx }>(
    () => api.get<{ transaction: LedgerTx }>(endpoints.ledgerTransaction(id)), [id],
  );
  const t = detail.data?.transaction;

  return (
    <Drawer title="Ledger transaction" sub={<IdentBadge id={id} kind="transaction" />} onClose={onClose}>
      {detail.loading && !t ? <LoadingState label="Loading transaction" /> : null}
      {detail.error ? <ErrorNotice error={detail.error} onRetry={detail.reload} /> : null}
      {t ? (
        <div className="stack">
          <Panel title="Record">
            <dl className="kv">
              <dt>Transaction ID</dt><dd>{t.tx_id}</dd>
              <dt>Event type</dt><dd>{t.event_type}</dd>
              <dt>Event ID</dt><dd><Hash value={t.event_id} chars={22} /></dd>
              <dt>Event hash</dt><dd><Hash value={t.event_hash} chars={22} /></dd>
              <dt>Recipient</dt><dd>{t.recipient_id}</dd>
              <dt>Document</dt><dd>{t.document_id}</dd>
              <dt>Session</dt><dd>{t.session_id}</dd>
              <dt>Watermark tag</dt><dd><Hash value={t.watermark_tag} chars={16} /></dd>
              <dt>Signature alg</dt><dd>{t.signature_algorithm}</dd>
              <dt>Signing key</dt><dd>{t.signing_key_id}</dd>
              <dt>Tx hash</dt><dd><Hash value={t.tx_hash} chars={22} /></dd>
              <dt>Committed block</dt><dd>{t.committed_block_id ?? "uncommitted"}</dd>
              <dt>Merkle index</dt><dd>{t.merkle_index ?? "—"}</dd>
              <dt>Committed at</dt><dd>{t.committed_at}</dd>
              <dt>Submitted by</dt><dd>{t.submitted_by_node}</dd>
            </dl>
          </Panel>

          <Panel title="Payload">
            <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap", color: "var(--tx-2)" }}>
              {JSON.stringify(t.payload, null, 2)}
            </pre>
          </Panel>
        </div>
      ) : null}
    </Drawer>
  );
}

/* --------------------------------------------------------- node admin */

export function Nodes() {
  const toast = useToast();
  const status = useAsync<LedgerStatus>(() => api.get<LedgerStatus>(endpoints.ledgerStatus), []);
  const [busy, setBusy] = useState<string | null>(null);

  const nodes = status.data?.nodes ?? [];

  const act = async (nodeId: string, action: string) => {
    setBusy(nodeId);
    try {
      await api.post(endpoints.nodesAdmin, { node_id: nodeId, action });
      toast.success(`Node ${action} requested`, nodeId);
      status.reload();
    } catch (e) {
      toast.failure("Node action refused", String((e as Error).message));
    } finally {
      setBusy(null);
    }
  };

  if (status.loading && !status.data) return <LoadingState label="Loading ledger nodes" detail="GET /ledger/status" />;
  if (status.error) {
    const st = (status.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={status.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={status.error} onRetry={status.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Ledger Nodes"
        sub="Three replicas with a quorum of two. An action is only committed once a majority holds it, so one lost or tampered node cannot rewrite history."
        actions={
          <>
            <QuorumChip nodes={nodes} quorumSize={status.data?.quorum_size ?? 2} />
            <button className="btn" onClick={status.reload} disabled={status.loading}>
              {status.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      <div className="grid g3">
        {nodes.map((n) => (
          <Panel key={n.node_id} title={n.node_id} actions={<StatusBadge status={n.status} lg />}>
            <dl className="kv">
              <dt>Block height</dt><dd>{n.block_height}</dd>
              <dt>Latest block</dt><dd><Hash value={n.latest_block_hash} chars={18} /></dd>
              <dt>Previous block</dt><dd><Hash value={n.previous_block_hash} chars={18} /></dd>
              <dt>Merkle root</dt><dd><Hash value={n.latest_merkle_root} chars={18} /></dd>
              <dt>State root</dt><dd><Hash value={n.state_root} chars={18} /></dd>
              <dt>Pending sync</dt><dd>{n.pending_sync_count}</dd>
            </dl>
            <div className="pill-row mt">
              <button className="btn sm" disabled={busy === n.node_id} onClick={() => act(n.node_id, "resync")}>Request resync</button>
              <button className="btn sm warn" disabled={busy === n.node_id} onClick={() => act(n.node_id, "seal")}>Force seal</button>
            </div>
          </Panel>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- sync */

function SyncModal({ nodes, onClose, onDone }: {
  nodes: LedgerNode[]; onClose: () => void; onDone: () => void;
}) {
  const toast = useToast();
  const [selected, setSelected] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const body = await api.post<Record<string, unknown>>(endpoints.ledgerSync, { offline_node_ids: selected });
      toast.success("Synchronisation requested", JSON.stringify(body).slice(0, 150));
      onDone();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Synchronise ledger nodes"
      sub="Queues the blocks each selected replica is missing."
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={run} disabled={busy}>
            {busy ? "Queueing…" : `Queue ${selected.length || "all"} node(s)`}
          </button>
        </>
      }
    >
      <Notice tone="info" title="Offline nodes catch up from their peers">
        Leave everything unchecked to request a sweep of every replica. Selecting nodes queues only those.
      </Notice>
      <div className="stack mt" style={{ gap: 6 }}>
        {nodes.map((n) => (
          <label key={n.node_id} className="flex-between" style={{ cursor: "pointer" }}>
            <span className="flex gap-sm">
              <input
                type="checkbox"
                checked={selected.includes(n.node_id)}
                onChange={(e) => setSelected((p) => e.target.checked ? [...p, n.node_id] : p.filter((x) => x !== n.node_id))}
              />
              <span className="mono">{n.node_id}</span>
            </span>
            <span className="flex gap-sm">
              <span className="tiny dim mono">h{n.block_height}</span>
              <StatusBadge status={n.status} />
            </span>
          </label>
        ))}
      </div>
      {error ? <div className="mt"><ErrorNotice error={error} /></div> : null}
    </Modal>
  );
}
