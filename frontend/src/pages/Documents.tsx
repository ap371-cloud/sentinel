import { useEffect, useMemo, useState } from "react";
import {
  api, ApiError, endpoints,
  type DecryptionResult, type DeviceRow, type DocumentDetail, type DocumentPolicy,
  type DocumentRow, type GrantRow, type GrantsResponse, type PolicyEditResult,
  type RecipientsResponse, type ShareRow, type SharesResponse,
} from "../api";
import {
  Badge, DataTable, Drawer, EmptyState, ErrorNotice, Field, FilterChips, Hash,
  LoadingState, Modal, Notice, PageHead, Panel, SearchInput, StatusBadge, Timeline,
  Unauthorized, useAsync, useToast,
} from "../components/ui";
import { IdentBadge } from "../components/layout";
import {
  ENFORCEMENT_LIMITATION, ENFORCEMENT_TONE, RIGHT_HONESTY,
  type EnforcementLevel,
} from "../components/enforcement";

type Filter = "all" | "active" | "sealed" | "suspended" | "revoked";

export function Documents({ permissions }: { permissions: string[] }) {
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

      {openId ? <DocumentDrawer id={openId} onClose={() => setOpenId(null)} onDecrypt={(d) => { setOpenId(null); setDecryptFor(d); }} permissions={permissions} /> : null}
      {decryptFor ? <DecryptModal document={decryptFor} onClose={() => setDecryptFor(null)} onDone={() => docs.reload()} /> : null}
    </div>
  );
}

/* ------------------------------------------------------------- drawer */

function DocumentDrawer({ id, onClose, onDecrypt, permissions }: {
  id: string; onClose: () => void; onDecrypt: (d: DocumentRow) => void; permissions: string[];
}) {
  const toast = useToast();
  const detail = useAsync<{ document: DocumentDetail }>(
    () => api.get<{ document: DocumentDetail }>(endpoints.document(id)), [id],
  );
  const [busy, setBusy] = useState<string | null>(null);
  const [editingPolicy, setEditingPolicy] = useState(false);

  const canEditPolicy = permissions.includes("policy.modify");
  const canGrant = permissions.includes("document.grant");
  const canRevoke = permissions.includes("recipient.revoke");

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

          <Panel
            title="Usage policy"
            actions={
              <span className="pill-row">
                <Badge tone="info">{d.policy.policy_version}</Badge>
                {canEditPolicy ? (
                  <button className="btn sm" onClick={() => setEditingPolicy(true)} disabled={d.status === "REVOKED"}>
                    Edit policy
                  </button>
                ) : null}
              </span>
            }
            flush
          >
            <RightsMatrix policy={d.policy} />
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

          <GrantsPanel documentId={d.document_id} canGrant={canGrant} canRevoke={canRevoke} />

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

      {editingPolicy && d ? (
        <PolicyEditor
          documentId={d.document_id}
          title={d.title}
          policy={d.policy}
          onClose={() => setEditingPolicy(false)}
          onSaved={() => { setEditingPolicy(false); detail.reload(); }}
        />
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

/* ------------------------------------------------------------- rights matrix */

function RightsMatrix({ policy }: { policy: DocumentPolicy }) {
  return (
    <>
      <DataTable
        rows={RIGHT_HONESTY}
        columns={[
          { key: "r", head: "Right", render: (h) => (
            <span className="stack" style={{ gap: 1 }}>
              <span className="mono">{h.right}</span>
              <span className="tiny dim" style={{ maxWidth: 300 }}>{h.note}</span>
            </span>
          ) },
          { key: "v", head: "Effective", render: (h) => <VerdictBadge verdict={(policy.rights ?? {})[h.right] ?? "DENY"} /> },
          { key: "s", head: "Decided by", render: (h) => <Badge tone="idle">{sourceLabel((policy.right_sources ?? {})[h.right])}</Badge> },
          { key: "e", head: "Enforcement on this stack", render: (h) => <EnforcementBadge level={h.level} /> },
        ]}
      />
      <div className="panel-body" style={{ borderTop: "1px solid var(--hair)" }}>
        <div className="tiny muted" style={{ lineHeight: 1.6 }}>{ENFORCEMENT_LIMITATION}</div>
      </div>
    </>
  );
}

function VerdictBadge({ verdict }: { verdict: string }) {
  return verdict === "ALLOW"
    ? <Badge tone="ok">ALLOW</Badge>
    : <Badge tone="crit">DENY</Badge>;
}

function EnforcementBadge({ level }: { level: EnforcementLevel }) {
  return <Badge tone={ENFORCEMENT_TONE[level]}>{level}</Badge>;
}

function sourceLabel(source?: string): string {
  if (!source) return "—";
  return source.replace(/_/g, " ");
}

/* ----------------------------------------------------------- grants & shares */

function GrantsPanel({ documentId, canGrant, canRevoke }: {
  documentId: string; canGrant: boolean; canRevoke: boolean;
}) {
  const toast = useToast();
  const grants = useAsync<GrantsResponse>(
    () => api.get<GrantsResponse>(endpoints.documentGrants(documentId)), [documentId],
  );
  const shares = useAsync<SharesResponse>(
    () => api.get<SharesResponse>(endpoints.documentShares(documentId)), [documentId],
  );
  const [granting, setGranting] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [revoking, setRevoking] = useState<GrantRow | null>(null);

  const refresh = () => { grants.reload(); shares.reload(); };

  return (
    <>
      <Panel
        title="Need-to-know grants"
        actions={
          canGrant ? (
            <span className="pill-row">
              <button className="btn sm" onClick={() => setGranting(true)}>+ Grant</button>
              <button className="btn sm" onClick={() => setSharing(true)}>⇄ Request share</button>
            </span>
          ) : <Badge tone="idle">READ-ONLY</Badge>
        }
        flush
      >
        {grants.error ? <ErrorNotice error={grants.error} onRetry={grants.reload} /> : null}
        {grants.loading && !grants.data ? <LoadingState label="Loading grants" /> : null}
        <DataTable
          rows={grants.data?.grants ?? []}
          empty={
            <EmptyState
              icon="⇄" title="Nobody holds need-to-know yet"
              sub={canGrant ? "Grant a recipient so they can be authorised for decryption." : "A document administrator decides need-to-know for this document."}
            />
          }
          columns={[
            { key: "r", head: "Recipient", render: (g) => (
              <span className="stack" style={{ gap: 1 }}>
                <IdentBadge id={g.recipient_id} kind="recipient" />
                <span className="tiny dim">{g.recipient_name ?? ""}{g.recipient_role ? ` · ${g.recipient_role}` : ""}</span>
              </span>
            ) },
            { key: "st", head: "Grant", render: (g) => <StatusBadge status={g.status} /> },
            { key: "x", head: "Expires", render: (g) => (
              <span className="tiny dim">{g.expires_at?.slice(0, 19).replace("T", " ") ?? "never"}</span>
            ) },
            { key: "by", head: "Granted by", render: (g) => <span className="mono">{g.granted_by}</span> },
            { key: "at", head: "At (UTC)", render: (g) => <span className="tiny dim">{g.granted_at.slice(0, 19).replace("T", " ")}</span> },
            { key: "n", head: "Note", render: (g) => <span className="tiny muted">{g.note ?? "—"}</span> },
            { key: "a", head: "", render: (g) => (
              canRevoke && g.status === "ACTIVE"
                ? <button className="btn sm danger" onClick={() => setRevoking(g)}>Revoke</button>
                : null
            ) },
          ]}
        />
      </Panel>

      <Panel title="Share register" flush>
        {shares.error ? <ErrorNotice error={shares.error} onRetry={shares.reload} /> : null}
        {shares.loading && !shares.data ? <LoadingState label="Loading share register" /> : null}
        <DataTable
          rows={shares.data?.shares ?? []}
          empty={<EmptyState icon="⇄" title="No shares requested" sub="External sharing requests appear here, including the ones routed to two-person approval." />}
          columns={[
            { key: "r", head: "Recipient", render: (s) => <IdentBadge id={s.recipient_id} kind="recipient" /> },
            { key: "st", head: "Status", render: (s) => <StatusBadge status={s.effective_status} /> },
            { key: "by", head: "Requested by", render: (s) => <span className="mono">{s.requested_by}</span> },
            { key: "at", head: "At (UTC)", render: (s) => <span className="tiny dim">{s.created_at.slice(0, 19).replace("T", " ")}</span> },
            { key: "x", head: "Expires", render: (s) => (
              <span className="tiny dim">{s.expires_at?.slice(0, 19).replace("T", " ") ?? "never"}</span>
            ) },
            { key: "j", head: "Justification", render: (s) => <span className="tiny muted" style={{ maxWidth: 260, display: "block" }}>{s.justification}</span> },
          ]}
        />
      </Panel>

      {granting ? (
        <GrantModal documentId={documentId} onClose={() => setGranting(false)} onDone={() => { refresh(); toast.success("Grant recorded", "Need-to-know was added for the recipient."); }} />
      ) : null}
      {sharing ? (
        <ShareModal documentId={documentId} onClose={() => setSharing(false)} onDone={() => { refresh(); toast.success("Share request raised", "The register now records it; approval may still be required."); }} />
      ) : null}
      {revoking ? (
        <RevokeModal grant={revoking} documentId={documentId} onClose={() => setRevoking(null)} onDone={() => { refresh(); toast.success("Access revoked", `${revoking.recipient_id} can no longer be authorised on this document.`); }} />
      ) : null}
    </>
  );
}

/* ------------------------------------------------------ grant / share modals */

function RecipientPicker({ value, onChange, exclude }: {
  value: string; onChange: (id: string) => void; exclude: string[];
}) {
  const directory = useAsync<RecipientsResponse>(() => api.get<RecipientsResponse>(endpoints.recipients), []);
  const options = (directory.data?.identities ?? [])
    .filter((i) => i.status === "ACTIVE" && !exclude.includes(i.recipient_id));
  if (!directory.data && directory.loading) return <LoadingState label="Loading the recipient directory" />;
  return (
    <select className="inp" value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">Choose an active recipient…</option>
      {options.map((i) => (
        <option key={i.recipient_id} value={i.recipient_id}>
          {i.recipient_id} — {i.display_name} ({i.role}, {i.clearance_label})
        </option>
      ))}
    </select>
  );
}

function GrantModal({ documentId, onClose, onDone }: {
  documentId: string; onClose: () => void; onDone: () => void;
}) {
  const [recipientId, setRecipientId] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(endpoints.documentGrants(documentId), { recipient_id: recipientId, note: note.trim() || undefined });
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
      title="Grant need-to-know"
      sub="Adds the recipient to the document's authorisation set."
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy || !recipientId} onClick={submit}>
            {busy ? "Granting…" : "Grant access"}
          </button>
        </>
      }
    >
      <Notice tone="info">
        Clearance and need-to-know are checked separately. The grant is recorded in the audit trail.
      </Notice>
      <div className="mt">
        <Field label="Recipient">
          <RecipientPicker value={recipientId} onChange={setRecipientId} exclude={[]} />
        </Field>
        <Field label="Note (optional)">
          <input className="inp" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Why this recipient needs access" />
        </Field>
      </div>
      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}

function ShareModal({ documentId, onClose, onDone }: {
  documentId: string; onClose: () => void; onDone: () => void;
}) {
  const [recipientId, setRecipientId] = useState("");
  const [justification, setJustification] = useState("");
  const [expiresIn, setExpiresIn] = useState("0");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(endpoints.documentShares(documentId), {
        recipient_id: recipientId,
        justification: justification.trim(),
        expires_in_days: Number(expiresIn),
      });
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
      title="Request external share"
      sub="Dual-controlled sharing: the request lands on the share register and routes to two-person approval when the policy requires it."
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy || !recipientId || justification.trim().length < 10} onClick={submit}>
            {busy ? "Raising…" : "Request share"}
          </button>
        </>
      }
    >
      <div className="mt">
        <Field label="Recipient">
          <RecipientPicker value={recipientId} onChange={setRecipientId} exclude={[]} />
        </Field>
        <Field label="Justification (min 10 chars)" hint="recorded verbatim on the register">
          <textarea className="inp" rows={3} value={justification} onChange={(e) => setJustification(e.target.value)} />
        </Field>
        <Field label="Expires in days (0 = no end date)">
          <input className="inp" type="number" min={0} max={365} value={expiresIn} onChange={(e) => setExpiresIn(e.target.value)} />
        </Field>
      </div>
      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}

function RevokeModal({ documentId, grant, onClose, onDone }: {
  documentId: string; grant: GrantRow; onClose: () => void; onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(endpoints.documentAccessRevoke(documentId), {
        recipient_id: grant.recipient_id,
        reason: reason.trim(),
      });
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
      title="Revoke document access"
      sub={<IdentBadge id={grant.recipient_id} kind="recipient" />}
      onClose={onClose}
      danger
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn danger" disabled={busy || reason.trim().length < 5} onClick={submit}>
            {busy ? "Revoking…" : "Revoke access"}
          </button>
        </>
      }
    >
      <Notice tone="warn" title="New authorisation is refused immediately">
        Records of what already happened stay untouched; the reason is written to the audit trail.
      </Notice>
      <div className="mt">
        <Field label="Reason (min 5 chars)">
          <input className="inp" value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
      </div>
      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}

/* ------------------------------------------------------------ policy editor */

const BOOL_FIELDS = [
  ["download_allowed", "Download"],
  ["print_allowed", "Print"],
  ["export_allowed", "Export"],
  ["offline_allowed", "Offline"],
  ["watermark_required", "Watermark required"],
  ["visible_watermark", "Visible watermark"],
  ["second_approval_required", "Second approval"],
] as const;

const OVERRIDABLE_RIGHTS = [
  "EDIT", "PRINT", "COPY", "DOWNLOAD", "EXPORT", "FORWARD", "SHARE", "SCREENSHOT", "OFFLINE",
];

function PolicyEditor({ documentId, title, policy, onClose, onSaved }: {
  documentId: string; title: string; policy: DocumentPolicy; onClose: () => void; onSaved: () => void;
}) {
  const toast = useToast();
  const [flags, setFlags] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(BOOL_FIELDS.map(([key]) => [key, policy[key]])));
  const [sessions, setSessions] = useState(String(policy.maximum_sessions));
  const [offlineHours, setOfflineHours] = useState(String(policy.offline_max_hours));
  const [expiryDays, setExpiryDays] = useState("");
  const [overrides, setOverrides] = useState<Record<string, "ALLOW" | "DENY">>({});
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const highClass = policy.classification === "SECRET" || policy.classification === "TOP_SECRET";

  const submit = async () => {
    if (reason.trim().length < 10) {
      setError(new Error("A written reason of at least 10 characters is required for a policy edit."));
      return;
    }
    const changes: Record<string, unknown> = {};
    for (const [key, value] of BOOL_FIELDS) {
      if (flags[key] !== policy[key]) changes[key] = flags[key];
    }
    const sessionsValue = Number(sessions);
    const hoursValue = Number(offlineHours);
    if (sessionsValue >= 0 && sessionsValue !== policy.maximum_sessions) changes.maximum_sessions = sessionsValue;
    if (hoursValue >= 0 && hoursValue !== policy.offline_max_hours) changes.offline_max_hours = hoursValue;
    const days = Number(expiryDays);
    if (days > 0) changes.access_expiry_days = days;
    if (Object.keys(overrides).length) changes.rights = overrides;

    setBusy(true);
    setError(null);
    try {
      const result = await api.put<PolicyEditResult>(endpoints.documentPolicy(documentId), {
        reason: reason.trim(),
        changes,
      });
      toast.success("Policy updated", `${Object.keys(result.changes).length} setting(s) recorded on the audit chain.`);
      onSaved();
    } catch (e) {
      setError(e);
      if (e instanceof ApiError) {
        toast.failure(
          e.status === 428 ? "Two-person approval required" : "Policy edit refused",
          e.detail || e.message,
        );
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Edit usage policy"
      sub={title}
      onClose={onClose}
      wide
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" disabled={busy} onClick={submit}>
            {busy ? "Applying…" : "Apply changes"}
          </button>
        </>
      }
    >
      <div className="stack">
        <Notice tone="warn" title="Every change is written to the audit chain with before/after verdicts">
          Leave a field untouched to keep the current value. Edits to SECRET / TOP_SECRET documents need a
          second identity's approval, so the first attempt may be refused with an approval reference.
        </Notice>

        <div className="grid g2">
          {BOOL_FIELDS.map(([key, label]) => (
            <Field key={key} label={label}>
              <select className="inp" value={flags[key] ? "allow" : "deny"} onChange={(e) => setFlags((f) => ({ ...f, [key]: e.target.value === "allow" }))}>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
            </Field>
          ))}
        </div>

        <div className="grid g3">
          <Field label="Maximum sessions (0 = no cap)">
            <input className="inp" type="number" min={0} max={10000} value={sessions} onChange={(e) => setSessions(e.target.value)} />
          </Field>
          <Field label="Offline max hours (0 = no cap)">
            <input className="inp" type="number" min={0} max={8760} value={offlineHours} onChange={(e) => setOfflineHours(e.target.value)} />
          </Field>
          <Field label="Reset expiry (days from now)">
            <input className="inp" type="number" min={1} max={3650} value={expiryDays} onChange={(e) => setExpiryDays(e.target.value)} placeholder="keep current" />
          </Field>
        </div>

        <div>
          <div className="tiny dim" style={{ letterSpacing: 1.1, textTransform: "uppercase", marginBottom: 5 }}>
            Per-right overrides {highClass ? <Badge tone="crit">HIGH CLASS</Badge> : null}
          </div>
          <div className="grid g3">
            {OVERRIDABLE_RIGHTS.map((right) => (
              <Field key={right} label={`${right} · now ${(policy.rights ?? {})[right] ?? "DENY"}`}>
                <select className="inp" value={overrides[right] ?? "keep"} onChange={(e) => {
                  const value = e.target.value as "keep" | "ALLOW" | "DENY";
                  setOverrides((prev) => {
                    const next = { ...prev };
                    if (value === "keep") delete next[right];
                    else next[right] = value;
                    return next;
                  });
                }}>
                  <option value="keep">Keep</option>
                  <option value="ALLOW">Allow</option>
                  <option value="DENY">Deny</option>
                </select>
              </Field>
            ))}
          </div>
        </div>

        <Field label="Reason (min 10 chars)" hint="read verbatim from the audit trail">
          <textarea className="inp" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
      </div>
      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
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
