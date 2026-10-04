import { useMemo, useState } from "react";
import {
  api, endpoints,
  type Approval, type DocumentRow,
} from "../api";
import {
  Badge, DataTable, EmptyState, ErrorNotice, Field, FilterChips, LoadingState, Metric,
  Modal, Notice, PageHead, Panel, SearchInput, StatusBadge, Unauthorized, useAsync, useToast,
} from "../components/ui";
import { IdentBadge } from "../components/layout";

type Filter = "all" | "PENDING" | "APPROVED" | "DENIED" | "EXPIRED";

type DecisionResponse = { approval?: Approval; sufficient?: boolean };

export function Approvals() {
  const toast = useToast();
  const approvals = useAsync<{ approvals: Approval[] }>(() => api.get(endpoints.approvals), []);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [busy, setBusy] = useState<string | null>(null);
  const [requestOpen, setRequestOpen] = useState(false);
  const [breakGlassOpen, setBreakGlassOpen] = useState(false);

  const rows = approvals.data?.approvals ?? [];
  const counts = useMemo(() => ({
    all: rows.length,
    PENDING: rows.filter((r) => r.status === "PENDING").length,
    APPROVED: rows.filter((r) => r.status === "APPROVED").length,
    DENIED: rows.filter((r) => r.status === "DENIED").length,
    EXPIRED: rows.filter((r) => r.status === "EXPIRED").length,
  }), [rows]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (filter !== "all" && r.status !== filter) return false;
      if (!needle) return true;
      return [r.approval_id, r.action, r.subject_id ?? "", r.justification, r.requested_by]
        .some((v) => v.toLowerCase().includes(needle));
    });
  }, [rows, q, filter]);

  const decide = async (a: Approval, decision: "approve" | "deny") => {
    setBusy(a.approval_id);
    try {
      const body = await api.post<DecisionResponse>(
        decision === "approve" ? endpoints.approvalApprove(a.approval_id) : endpoints.approvalDeny(a.approval_id),
        { reason: decision === "approve" ? "Approved from the command terminal" : "Denied from the command terminal" },
      );
      const refreshed = body.approval ?? a;
      toast.success(
        decision === "approve" ? "Approval recorded" : "Request denied",
        refreshed.sufficient
          ? "The backend confirmed quorum for this request."
          : `Your vote is recorded, but ${refreshed.approvals_remaining} more approval(s) are required before it can execute.`,
      );
      approvals.reload();
    } catch (e) {
      toast.failure("Decision refused", String((e as Error).message));
    } finally {
      setBusy(null);
    }
  };

  if (approvals.loading && !approvals.data) return <LoadingState label="Loading approval queue" detail="GET /approvals" />;
  if (approvals.error) {
    const st = (approvals.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={approvals.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={approvals.error} onRetry={approvals.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Approvals & Break-Glass"
        sub="Dual control. Nothing sensitive executes on one officer's word — the backend counts approvals and refuses to act until quorum is reached."
        actions={
          <>
            <button className="btn warn" onClick={() => setBreakGlassOpen(true)}>⚿ Request break-glass</button>
            <button className="btn primary" onClick={() => setRequestOpen(true)}>+ New approval request</button>
            <button className="btn" onClick={approvals.reload} disabled={approvals.loading}>
              {approvals.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      <Notice tone="info" title="How quorum works here">
        Each request declares how many approvals it needs (2 or 3). Approvers are recorded individually. The action
        only becomes executable when the recorded count reaches the requirement — the console never assumes consent.
      </Notice>

      <div className="grid g4">
        <Metric label="Pending" value={counts.PENDING} tone={counts.PENDING ? "warn" : "ok"} sub="awaiting officer votes" />
        <Metric label="Approved" value={counts.APPROVED} tone="ok" sub="quorum recorded" />
        <Metric label="Denied" value={counts.DENIED} tone={counts.DENIED ? "crit" : "ok"} sub="refused by an officer" />
        <Metric label="Expired" value={counts.EXPIRED} tone={counts.EXPIRED ? "warn" : "ok"} sub="lapsed before quorum" />
      </div>

      <Panel flush>
        <div className="panel-body" style={{ borderBottom: "1px solid var(--hair)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <SearchInput value={q} onChange={setQ} placeholder="Search action, subject, requester, justification…" width={340} />
          <FilterChips
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All", count: counts.all },
              { value: "PENDING", label: "Pending", count: counts.PENDING },
              { value: "APPROVED", label: "Approved", count: counts.APPROVED },
              { value: "DENIED", label: "Denied", count: counts.DENIED },
              { value: "EXPIRED", label: "Expired", count: counts.EXPIRED },
            ]}
          />
          <span className="tiny dim" style={{ marginLeft: "auto" }}>{filtered.length} of {rows.length} shown</span>
        </div>

        <DataTable
          rows={filtered}
          empty={<EmptyState icon="⚿" title="No approval requests" sub={q ? `Nothing matches “${q}”.` : "No dual-control request is open right now."} />}
          columns={[
            { key: "a", head: "Action", render: (r) => (
              <span className="stack" style={{ gap: 2 }}>
                <span>{r.action.replace(/[._]/g, " ")}</span>
                <span className="tiny dim">by {r.requested_by}</span>
              </span>
            ) },
            { key: "s", head: "Subject", render: (r) => <IdentBadge id={r.subject_id} kind="subject" /> },
            { key: "j", head: "Justification", render: (r) => <span className="tiny muted" style={{ maxWidth: 320, display: "block" }}>{r.justification}</span> },
            { key: "q", head: "Approvals", render: (r) => (
              <span className="flex gap-sm">
                <span className="mono">{r.approvals_counted}/{r.required_approvals}</span>
                {r.sufficient ? <Badge tone="ok">QUORUM</Badge> : <Badge tone="warn">{r.approvals_remaining} MORE</Badge>}
              </span>
            ) },
            { key: "st", head: "Status", render: (r) => (
              <span className="flex gap-sm">
                <StatusBadge status={r.status} />
                {r.consumed ? <Badge tone="info">CONSUMED</Badge> : null}
              </span>
            ) },
            { key: "e", head: "Expires", render: (r) => <span className="tiny dim">{r.expires_at?.slice(0, 19).replace("T", " ")}</span> },
            {
              key: "act", head: "Decision", render: (r) => (
                r.status !== "PENDING" ? <span className="dim tiny">—</span> : (
                  <span className="flex gap-sm">
                    <button className="btn sm primary" disabled={busy === r.approval_id} onClick={() => decide(r, "approve")}>Approve</button>
                    <button className="btn sm danger" disabled={busy === r.approval_id} onClick={() => decide(r, "deny")}>Deny</button>
                  </span>
                )
              ),
            },
          ]}
        />
      </Panel>

      {requestOpen ? <NewRequest onClose={() => setRequestOpen(false)} onDone={() => approvals.reload()} /> : null}
      {breakGlassOpen ? <BreakGlass onClose={() => setBreakGlassOpen(false)} onDone={() => approvals.reload()} /> : null}
    </div>
  );
}

/* ------------------------------------------------------- new request */

function NewRequest({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [action, setAction] = useState("recipient.revoke");
  const [subject, setSubject] = useState("");
  const [justification, setJustification] = useState("");
  const [required, setRequired] = useState(2);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(endpoints.approvals, {
        action,
        subject_id: subject.trim() || null,
        justification,
        required_approvals: required,
      });
      toast.success("Approval request opened", `${required} approval(s) required before it can execute.`);
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
      title="New approval request"
      sub="Opens a dual-control request. It does not execute anything yet."
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={submit} disabled={busy || justification.trim().length < 10}>
            {busy ? "Submitting…" : "Open request"}
          </button>
        </>
      }
    >
      <Field label="Action">
        <select className="inp" value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="recipient.revoke">recipient.revoke — revoke an identity</option>
          <option value="document.suspend">document.suspend — suspend a document</option>
          <option value="device.revoke">device.revoke — revoke a device</option>
          <option value="ledger.sync">ledger.sync — force ledger synchronisation</option>
        </select>
      </Field>

      <Field label="Subject ID" hint="optional">
        <input className="inp" value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="e.g. RECIPIENT-002" />
      </Field>

      <Field label="Justification" hint={`${justification.trim().length}/10 minimum`}>
        <textarea className="inp" rows={3} value={justification} onChange={(e) => setJustification(e.target.value)}
          placeholder="Why is this action necessary? The text is written to the audit trail verbatim." />
      </Field>

      <Field label="Approvals required">
        <select className="inp" value={required} onChange={(e) => setRequired(Number(e.target.value))}>
          <option value={2}>2 — standard dual control</option>
          <option value={3}>3 — elevated, for irreversible actions</option>
        </select>
      </Field>

      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}

/* --------------------------------------------------------- break-glass */

function BreakGlass({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const docs = useAsync<{ documents: DocumentRow[] }>(() => api.get(endpoints.documents), []);
  const [documentId, setDocumentId] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(endpoints.breakGlass, { document_id: documentId, reason });
      toast.success("Break-glass request submitted", "It stays inert until the required second approval is recorded.");
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
      title="Request break-glass access"
      sub="Bypasses a normal authorisation rule. There is no single-officer path."
      onClose={onClose}
      danger
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn danger" onClick={submit} disabled={busy || !documentId || reason.trim().length < 15}>
            {busy ? "Submitting…" : "⚿ Submit request"}
          </button>
        </>
      }
    >
      <Notice tone="crit" title="This is the most sensitive action in the console">
        Break-glass exists for continuity of command when normal authorisation would fail. The request is recorded
        with your identity, it requires a second officer, and it is anchored on the ledger before any access happens.
      </Notice>

      <div className="mt">
        <Field label="Document">
          {docs.loading ? <LoadingState label="Loading documents" /> : (
            <select className="inp" value={documentId} onChange={(e) => setDocumentId(e.target.value)}>
              <option value="">Select a document…</option>
              {(docs.data?.documents ?? []).map((d) => (
                <option key={d.document_id} value={d.document_id}>{d.document_id} — {d.title}</option>
              ))}
            </select>
          )}
        </Field>

        <Field label="Justification" hint={`${reason.trim().length}/15 minimum`}>
          <textarea className="inp" rows={4} value={reason} onChange={(e) => setReason(e.target.value)}
            placeholder="Operational necessity. Why normal authorisation cannot be used." />
        </Field>
      </div>

      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}
