import { useEffect, useMemo, useState } from "react";
import {
  api, endpoints,
  type DecryptionResult, type DeviceRow, type DocumentDetail, type DocumentRow,
} from "../api";
import {
  Badge, DataTable, Drawer, EmptyState, ErrorNotice, Field, FilterChips, Hash,
  LoadingState, Modal, Notice, PageHead, Panel, SearchInput, StatusBadge, Timeline,
  Unauthorized, useAsync, useToast,
} from "../components/ui";
import { IdentBadge } from "../components/layout";

type Filter = "all" | "active" | "sealed" | "suspended" | "revoked";

export function Documents() {
  const docs = useAsync<{ documents: DocumentRow[] }>(() => api.get(endpoints.documents), []);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [openId, setOpenId] = useState<string | null>(null);
  const [decryptFor, setDecryptFor] = useState<DocumentRow | null>(null);

  const rows = docs.data?.documents ?? [];

  const counts = useMemo(() => ({
    all: rows.length,
    active: rows.filter((r) => r.status === "ACTIVE").length,
    sealed: rows.filter((r) => r.lifecycle_state === "SEALED").length,
    suspended: rows.filter((r) => r.status === "SUSPENDED").length,
    revoked: rows.filter((r) => r.status === "REVOKED").length,
  }), [rows]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      const okFilter =
        filter === "all" ? true :
        filter === "sealed" ? r.lifecycle_state === "SEALED" :
        r.status === filter.toUpperCase();
      if (!okFilter) return false;
      if (!needle) return true;
      return [r.document_id, r.title, r.owning_unit, r.classification_label, r.classification]
        .some((v) => v?.toLowerCase().includes(needle));
    });
  }, [rows, q, filter]);

  if (docs.loading && !docs.data) return <LoadingState label="Loading document register" detail="GET /documents" />;
  if (docs.error) {
    const status = (docs.error as { status?: number }).status;
    return status === 401 || status === 403
      ? <Unauthorized error={docs.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={docs.error} onRetry={docs.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Documents"
        sub="Every protected artefact, its version history, key wraps and lifecycle state. Decryption is authorised per session and watermarked per recipient."
        actions={
          <>
            <Badge tone="info">{rows.length} REGISTERED</Badge>
            <button className="btn" onClick={docs.reload} disabled={docs.loading}>
              {docs.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      <Panel flush>
        <div className="panel-body" style={{ borderBottom: "1px solid var(--hair)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <SearchInput value={q} onChange={setQ} placeholder="Search ID, title, unit, classification…" width={340} />
          <FilterChips
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All", count: counts.all },
              { value: "active", label: "Active", count: counts.active },
              { value: "sealed", label: "Sealed", count: counts.sealed },
              { value: "suspended", label: "Suspended", count: counts.suspended },
              { value: "revoked", label: "Revoked", count: counts.revoked },
            ]}
          />
          <span className="tiny dim" style={{ marginLeft: "auto" }}>
            {filtered.length} of {rows.length} shown
          </span>
        </div>

        <DataTable
          rows={filtered}
          onRow={(r) => setOpenId(r.document_id)}
          empty={
            <EmptyState
              icon="▤"
              title="No documents match"
              sub={q ? `Nothing matches “${q}” with the ${filter} filter. Clear the search to see the full register.` : "The register is empty for this filter."}
              action={q || filter !== "all" ? (
                <button className="btn" onClick={() => { setQ(""); setFilter("all"); }}>Clear filters</button>
              ) : undefined}
            />
          }
          columns={[
            { key: "t", head: "Title", render: (r) => (
              <span className="stack" style={{ gap: 2 }}>
                <span>{r.title}</span>
                <span className="tiny dim">{r.owning_unit}</span>
              </span>
            ) },
            { key: "id", head: "Document ID", render: (r) => <IdentBadge id={r.document_id} /> },
            { key: "c", head: "Classification", render: (r) => <Badge tone={r.classification === "TOP_SECRET" ? "crit" : r.classification === "SECRET" ? "high" : "info"}>{r.classification_label}</Badge> },
            { key: "v", head: "Ver", num: true, render: (r) => r.current_version },
            { key: "r", head: "Recipients", num: true, render: (r) => r.authorized_recipients.length },
            { key: "s", head: "Sessions", num: true, render: (r) => `${r.sessions_used}/${r.maximum_sessions}` },
            { key: "st", head: "Status", render: (r) => (
              <span className="flex gap-sm">
                <StatusBadge status={r.status} />
                <StatusBadge status={r.lifecycle_state} />
              </span>
            ) },
            { key: "h", head: "SHA-256", render: (r) => <Hash value={r.current_version_sha256} chars={12} /> },
          ]}
        />
      </Panel>

      {openId ? <DocumentDrawer id={openId} onClose={() => setOpenId(null)} onDecrypt={(d) => { setOpenId(null); setDecryptFor(d); }} /> : null}
      {decryptFor ? <DecryptModal document={decryptFor} onClose={() => setDecryptFor(null)} onDone={() => docs.reload()} /> : null}
    </div>
  );
}

/* ------------------------------------------------------------- drawer */

function DocumentDrawer({ id, onClose, onDecrypt }: {
  id: string; onClose: () => void; onDecrypt: (d: DocumentRow) => void;
}) {
  const toast = useToast();
  const detail = useAsync<{ document: DocumentDetail }>(
    () => api.get<{ document: DocumentDetail }>(endpoints.document(id)), [id],
  );
  const [busy, setBusy] = useState<string | null>(null);

  const act = async (label: string, path: string, body?: unknown) => {
    setBusy(label);
    try {
      await api.post(path, body ?? {});
      toast.success(label, `The backend accepted the request for ${id}.`);
      detail.reload();
    } catch (e) {
      toast.failure(`${label} refused`, String((e as Error).message));
    } finally {
      setBusy(null);
    }
  };

  const d = detail.data?.document;

  return (
    <Drawer
      title={d?.title ?? id}
      sub={<IdentBadge id={id} />}
      onClose={onClose}
      actions={
        d ? (
          <button className="btn primary sm" onClick={() => onDecrypt(d)} disabled={d.status !== "ACTIVE"}>
            ⊛ Authorised decryption
          </button>
        ) : null
      }
    >
      {detail.loading && !d ? <LoadingState label="Loading document record" /> : null}
      {detail.error ? <ErrorNotice error={detail.error} onRetry={detail.reload} /> : null}

      {d ? (
        <div className="stack">
          <div className="grid g4">
            <KV k="Classification" v={<Badge tone={d.classification === "TOP_SECRET" ? "crit" : "info"}>{d.classification_label}</Badge>} />
            <KV k="Status" v={<StatusBadge status={d.status} />} />
            <KV k="Lifecycle" v={<StatusBadge status={d.lifecycle_state} />} />
            <KV k="Owning unit" v={d.owning_unit} />
          </div>

          <Panel title="Cryptography" tone="ok">
            <dl className="kv">
              <dt>Content cipher</dt><dd>{d.crypto.content_cipher}</dd>
              <dt>Key wrap</dt><dd>{d.crypto.key_wrap}</dd>
            </dl>
            <div className="tiny muted" style={{ marginTop: 7 }}>{d.crypto.content_note}</div>
          </Panel>

          <Panel title="Live policy" actions={<Badge tone="info">v{d.versions.find((v) => v.is_current)?.version_number ?? d.current_version}</Badge>}>
            <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap", color: "var(--tx-2)" }}>
              {JSON.stringify(d.policy, null, 2)}
            </pre>
          </Panel>

          <Panel title="Versions" flush>
            <DataTable
              rows={d.versions}
              empty={<EmptyState title="No versions" sub="This document has no stored versions." />}
              columns={[
                { key: "n", head: "#", num: true, render: (v) => v.version_number },
                { key: "l", head: "Label", render: (v) => <span className="flex gap-sm">{v.label}{v.is_current ? <Badge tone="ok">CURRENT</Badge> : null}</span> },
                { key: "w", head: "Key wraps", num: true, render: (v) => v.recipient_key_wraps },
                { key: "a", head: "Wrap alg", render: (v) => <span className="mono">{v.key_wrap_algorithm}</span> },
                { key: "h", head: "SHA-256", render: (v) => <Hash value={v.content_sha256} chars={12} /> },
                { key: "t", head: "Created", render: (v) => <span className="tiny dim">{v.created_at?.slice(0, 19).replace("T", " ")}</span> },
              ]}
            />
          </Panel>

          <Panel title="Access history" flush>
            <DataTable
              rows={d.access_history}
              empty={<EmptyState icon="⊛" title="No access yet" sub="Nobody has decrypted this document." />}
              columns={[
                { key: "s", head: "Session", render: (a) => <IdentBadge id={a.session_id} kind="session" /> },
                { key: "r", head: "Recipient", render: (a) => <span className="mono">{a.recipient_id}</span> },
                { key: "d", head: "Device", render: (a) => <span className="mono">{a.device_id}</span> },
                { key: "v", head: "Ver", num: true, render: (a) => a.version_number },
                { key: "st", head: "Status", render: (a) => (
                  <span className="flex gap-sm">
                    <StatusBadge status={a.status} />
                    {a.break_glass ? <Badge tone="crit">BREAK-GLASS</Badge> : null}
                  </span>
                ) },
                { key: "t", head: "Issued", render: (a) => <span className="tiny dim">{a.issued_at?.slice(0, 19).replace("T", " ")}</span> },
              ]}
            />
          </Panel>

          {d.lifecycle_history.length ? (
            <Panel title="Lifecycle transitions" flush>
              <Timeline
                items={d.lifecycle_history.map((h, i) => ({
                  id: `${h.at}-${i}`,
                  time: h.at,
                  title: `${h.from} → ${h.to}`,
                  detail: h.reason,
                }))}
              />
            </Panel>
          ) : null}

          <Panel title="Administrative actions" tone={d.status === "ACTIVE" ? undefined : "warn"}>
            <Notice tone="warn" title="These actions change real state">
              Every request below is authorised by the backend against your clearance and written to the audit trail.
            </Notice>
            <div className="pill-row mt">
              <button className="btn sm" disabled={busy !== null} onClick={() => act("Lifecycle advanced", endpoints.documentLifecycle(id))}>
                Advance lifecycle
              </button>
              <button className="btn sm warn" disabled={busy !== null || d.status !== "ACTIVE"} onClick={() => act("Document suspended", endpoints.documentSuspend(id))}>
                Suspend
              </button>
              <button className="btn sm danger" disabled={busy !== null} onClick={() => act("Plaintext purge requested", endpoints.purgePlaintext(id))}>
                Purge plaintext
              </button>
            </div>
          </Panel>
        </div>
      ) : null}
    </Drawer>
  );
}

function KV({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div>
      <div className="tiny dim" style={{ letterSpacing: 1.1, textTransform: "uppercase" }}>{k}</div>
      <div style={{ marginTop: 3 }}>{v}</div>
    </div>
  );
}

/* ------------------------------------------------------------- decrypt */

function DecryptModal({ document, onClose, onDone }: {
  document: DocumentRow; onClose: () => void; onDone: () => void;
}) {
  const toast = useToast();
  const devices = useAsync<{ devices: DeviceRow[] }>(() => api.get(endpoints.devices), []);
  const [deviceId, setDeviceId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<DecryptionResult | null>(null);

  useEffect(() => {
    if (!deviceId && devices.data?.devices.length) setDeviceId(devices.data.devices[0].device_id);
  }, [devices.data, deviceId]);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const auth = await api.post<{ nonce: string }>(endpoints.authorise, { document_id: document.document_id });
      const body = await api.post<DecryptionResult>(endpoints.decrypt, {
        document_id: document.document_id, device_id: deviceId, nonce: auth.nonce,
      });
      setResult(body);
      toast.success("Decryption authorised", "Watermark embedded and ledger transaction committed.");
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  // A recipient can only decrypt on their own active device; the backend refuses
  // anything else, so the picker does not offer it in the first place.
  const eligible = (devices.data?.devices ?? []).filter(
    (d) => d.status === "ACTIVE" && d.trust_state !== "REVOKED",
  );

  return (
    <Modal
      title="Authorised decryption"
      sub={`${document.title} · version ${document.current_version}`}
      onClose={onClose}
      wide
      footer={
        <>
          <button className="btn" onClick={onClose}>{result ? "Close" : "Cancel"}</button>
          <button className="btn primary" onClick={run} disabled={busy || !deviceId || !!result}>
            {busy ? "Authorising…" : "⊛ Authorise & decrypt"}
          </button>
        </>
      }
    >
      {!result ? (
        <>
          <Notice tone="info" title="Two server-side steps, one nonce">
            The backend issues a single-use authorisation nonce, then consumes it. Replaying a nonce is detected
            and recorded as a security event. The output is watermarked for this recipient and device.
          </Notice>

          <div className="mt">
            <Field label="Document">
              <input className="inp" value={`${document.document_id} — ${document.title}`} readOnly />
            </Field>
            <Field label="Device" hint="must be registered and trusted">
              <select className="inp" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} disabled={busy}>
                {eligible.length === 0 ? <option value="">No trusted device available</option> : null}
                {eligible.map((d) => (
                  <option key={d.device_id} value={d.device_id}>
                    {d.device_id} — {d.device_name} ({d.trust_state})
                  </option>
                ))}
              </select>
            </Field>
          </div>

          {error ? <ErrorNotice error={error} /> : null}
          {busy ? <LoadingState label="Requesting authorisation nonce" detail="POST /decrypt/authorize" /> : null}
        </>
      ) : (
        <div className="stack">
          <div className={`evidence ${result.ledger.committed ? "" : "warn"}`}>
            <h2>{result.ledger.committed ? "DECRYPTION COMMITTED" : "DECRYPTED · LEDGER PENDING"}</h2>
            <div className="sub">{result.viewer_note}</div>
            <div className="confidence-ring">
              <b>{result.watermark_quality.psnr_db.toFixed(1)}</b>
              <span>dB watermark PSNR · SSIM {result.watermark_quality.ssim}</span>
            </div>
          </div>

          <div className="grid g4">
            <KV k="Session" v={<IdentBadge id={result.session_id} kind="session" />} />
            <KV k="Watermark tag" v={<span className="mono">{result.watermark_tag}</span>} />
            <KV k="Ledger" v={<StatusBadge status={result.ledger.status} />} />
            <KV k="Carriers / bit" v={<span className="mono">{result.watermark_quality.carriers_per_bit}</span>} />
          </div>

          <Panel title="Authorisation checks" flush>
            <div className="pipeline">
              {result.authorization_checks.map((c) => (
                <div key={c.check} className={`vstep ${c.passed ? "pass" : "fail"}`}>
                  <span className="mark">{c.passed ? "✓" : "✕"}</span>
                  <div>
                    <div className="nm">{c.check}</div>
                    <div className="dt mono">{c.reason_code}</div>
                  </div>
                  <div className="st"><StatusBadge status={c.passed ? "PASS" : "FAIL"} /></div>
                </div>
              ))}
            </div>
          </Panel>

          <Notice tone="ok" title="Watermark bound to this recipient">
            Tag <span className="mono">{result.watermark_tag}</span> is keyed to session{" "}
            <span className="mono">{result.session_id}</span>. If this copy is later found outside the system,
            the forensic extractor can recover the tag and link it to this session.
          </Notice>
        </div>
      )}
    </Modal>
  );
}
