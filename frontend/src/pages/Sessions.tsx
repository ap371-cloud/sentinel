import { useMemo, useState } from "react";
import {
  api, endpoints,
  type SessionDetail, type SessionRow,
} from "../api";
import {
  Badge, DataTable, Drawer, EmptyState, ErrorNotice, FilterChips, Hash, LoadingState,
  Notice, PageHead, Panel, Pipeline, SearchInput, StatusBadge,
  Unauthorized, VerificationStep, useAsync,
} from "../components/ui";
import { IdentBadge } from "../components/layout";

type Filter = "all" | "active" | "completed" | "break_glass";

export function Sessions() {
  const sessions = useAsync<{ sessions: SessionRow[] }>(() => api.get(endpoints.sessions), []);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [openId, setOpenId] = useState<string | null>(null);

  const rows = sessions.data?.sessions ?? [];

  const counts = useMemo(() => ({
    all: rows.length,
    active: rows.filter((r) => r.status === "ACTIVE").length,
    completed: rows.filter((r) => r.status === "COMPLETED").length,
    break_glass: rows.filter((r) => r.break_glass).length,
  }), [rows]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      const ok = filter === "all" ? true : filter === "break_glass" ? r.break_glass : r.status === filter.toUpperCase();
      if (!ok) return false;
      if (!needle) return true;
      return [r.session_id, r.recipient_id, r.document_id, r.device_id, r.watermark_tag ?? ""]
        .some((v) => v.toLowerCase().includes(needle));
    });
  }, [rows, q, filter]);

  if (sessions.loading && !sessions.data) return <LoadingState label="Loading decryption sessions" detail="GET /sessions" />;
  if (sessions.error) {
    const st = (sessions.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={sessions.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={sessions.error} onRetry={sessions.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Decryption Sessions"
        sub="Each session is one authorised opening of one document version on one device. The session nonce is single-use and the watermark is keyed to it."
        actions={
          <>
            <Badge tone="info">{rows.length} SESSIONS</Badge>
            <button className="btn" onClick={sessions.reload} disabled={sessions.loading}>
              {sessions.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      {counts.break_glass > 0 ? (
        <Notice tone="crit" title={`${counts.break_glass} break-glass session(s) recorded`}>
          Break-glass access bypasses the routine authorisation path and always requires a second approval. Review
          each one in the Approvals console.
        </Notice>
      ) : null}

      <Panel flush>
        <div className="panel-body" style={{ borderBottom: "1px solid var(--hair)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <SearchInput value={q} onChange={setQ} placeholder="Search session, recipient, document, device, watermark tag…" width={380} />
          <FilterChips
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All", count: counts.all },
              { value: "active", label: "Active", count: counts.active },
              { value: "completed", label: "Completed", count: counts.completed },
              { value: "break_glass", label: "Break-glass", count: counts.break_glass },
            ]}
          />
          <span className="tiny dim" style={{ marginLeft: "auto" }}>{filtered.length} of {rows.length} shown</span>
        </div>

        <DataTable
          rows={filtered}
          onRow={(r) => setOpenId(r.session_id)}
          empty={
            <EmptyState
              icon="⊛"
              title="No sessions match"
              sub={q ? `Nothing matches “${q}”.` : "No decryption session has been issued under the current filter."}
              action={q || filter !== "all" ? <button className="btn" onClick={() => { setQ(""); setFilter("all"); }}>Clear filters</button> : undefined}
            />
          }
          columns={[
            { key: "s", head: "Session ID", render: (r) => <IdentBadge id={r.session_id} kind="session" /> },
            { key: "r", head: "Recipient", render: (r) => <span className="mono">{r.recipient_id}</span> },
            { key: "d", head: "Document", render: (r) => <IdentBadge id={r.document_id} /> },
            { key: "v", head: "Ver", num: true, render: (r) => r.version_number },
            { key: "dev", head: "Device", render: (r) => <span className="mono">{r.device_id}</span> },
            { key: "w", head: "Watermark", render: (r) => <Hash value={r.watermark_tag} chars={10} /> },
            { key: "st", head: "Status", render: (r) => (
              <span className="flex gap-sm">
                <StatusBadge status={r.status} />
                {r.break_glass ? <Badge tone="crit">BREAK-GLASS</Badge> : null}
              </span>
            ) },
            { key: "t", head: "Issued (UTC)", render: (r) => <span className="tiny dim">{r.issued_at?.slice(0, 19).replace("T", " ")}</span> },
          ]}
        />
      </Panel>

      {openId ? <SessionDrawer id={openId} onClose={() => setOpenId(null)} /> : null}
    </div>
  );
}

function SessionDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const detail = useAsync<{ session: SessionDetail }>(
    () => api.get<{ session: SessionDetail }>(endpoints.session(id)), [id],
  );
  const evidence = useAsync<Record<string, unknown>>(
    () => api.get(endpoints.sessionEvidence(id)), [id],
  );
  const s = detail.data?.session;

  return (
    <Drawer title="Decryption session" sub={<IdentBadge id={id} kind="session" />} onClose={onClose}>
      {detail.loading && !s ? <LoadingState label="Loading session record" /> : null}
      {detail.error ? <ErrorNotice error={detail.error} onRetry={detail.reload} /> : null}

      {s ? (
        <div className="stack">
          <div className="flex wrap gap-sm">
            <StatusBadge status={s.status} lg />
            {s.break_glass ? <Badge tone="crit" lg>BREAK-GLASS</Badge> : null}
            <Badge tone={s.ledger_committed ? "ok" : "warn"} lg>
              LEDGER {s.ledger_committed ? "COMMITTED" : "PENDING"}
            </Badge>
          </div>

          <Panel title="Authorisation checks" flush>
            <Pipeline>
              {s.authorization_checks.map((c) => (
                <VerificationStep
                  key={c.check}
                  state={c.passed ? "pass" : "fail"}
                  name={c.check}
                  detail={c.plain_explanation}
                  right={<span className="mono tiny dim">{c.reason_code}</span>}
                />
              ))}
            </Pipeline>
          </Panel>

          <Panel title="Watermark binding">
            <dl className="kv">
              <dt>Watermark ID</dt><dd><Hash value={s.watermark_id} chars={20} /></dd>
              <dt>Tag</dt><dd><Hash value={s.watermark_tag} chars={20} /></dd>
              <dt>Version</dt><dd>{s.watermark_version}</dd>
              {s.watermark_quality ? (
                <>
                  <dt>PSNR</dt><dd>{s.watermark_quality.psnr_db} dB</dd>
                  <dt>SSIM</dt><dd>{s.watermark_quality.ssim}</dd>
                  <dt>Carriers / bit</dt><dd>{s.watermark_quality.carriers_per_bit}</dd>
                </>
              ) : null}
            </dl>
            <div className="hr" />
            <div className="tiny muted">
              The tag is derived from this session, so recovering it from an external copy links that copy to this
              exact opening — not merely to the document.
            </div>
          </Panel>

          <Panel title="Cryptographic signature" tone={s.signature ? "ok" : "warn"}>
            {s.signature ? (
              <>
                <dl className="kv">
                  <dt>Event ID</dt><dd><Hash value={s.signature.event_id} chars={20} /></dd>
                  <dt>Event hash</dt><dd><Hash value={s.signature.event_hash} chars={20} /></dd>
                  <dt>Algorithm</dt><dd>{s.signature.algorithm}</dd>
                  <dt>Signing key</dt><dd>{s.signature.signing_key_id}</dd>
                  <dt>Previous hash</dt><dd><Hash value={s.signature.prev_event_hash} chars={20} /></dd>
                  <dt>Signature</dt><dd><Hash value={s.signature.signature} chars={24} /></dd>
                </dl>
                <div className="tiny muted" style={{ marginTop: 7 }}>
                  Signature is verified by the backend. The UI only reports what verification returned.
                </div>
              </>
            ) : (
              <Notice tone="warn" title="No signature on this session">
                The backend did not return a signature for this record, so nothing is being claimed about its integrity.
              </Notice>
            )}
          </Panel>

          <Panel title="Ledger anchor">
            <dl className="kv">
              <dt>Transaction</dt><dd><Hash value={s.ledger_tx_id} chars={20} /></dd>
              <dt>Committed</dt><dd><StatusBadge status={s.ledger_committed ? "COMMITTED" : "PENDING"} /></dd>
              <dt>Policy version</dt><dd>{s.policy_version}</dd>
              <dt>Request ID</dt><dd><Hash value={s.request_id} chars={20} /></dd>
            </dl>
          </Panel>

          <Panel title="Evidence chain" flush>
            {evidence.loading ? <LoadingState label="Loading evidence chain" /> : null}
            {evidence.error ? <ErrorNotice error={evidence.error} onRetry={evidence.reload} /> : null}
            {evidence.data ? (
              <div style={{ padding: "12px 14px" }}>
                <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap", color: "var(--tx-2)" }}>
                  {JSON.stringify(evidence.data, null, 2)}
                </pre>
              </div>
            ) : null}
          </Panel>
        </div>
      ) : null}
    </Drawer>
  );
}
