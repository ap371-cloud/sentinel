import { useMemo, useState } from "react";
import {
  api, endpoints,
  type InvestigationRow,
} from "../api";
import {
  Badge, DataTable, Drawer, EmptyState, ErrorNotice, Field, FilterChips, Hash,
  LoadingState, Metric, Modal, Notice, PageHead, Panel, SearchInput, StatusBadge,
  Timeline, Unauthorized, useAsync, useToast,
} from "../components/ui";
import { IdentBadge } from "../components/layout";

export function Investigations() {
  const toast = useToast();
  const cases = useAsync<{ cases: InvestigationRow[] }>(() => api.get(endpoints.investigations), []);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"all" | "OPEN" | "CLOSED">("all");
  const [openId, setOpenId] = useState<string | null>(null);
  const [newOpen, setNewOpen] = useState(false);

  const rows = cases.data?.cases ?? [];
  const counts = useMemo(() => ({
    all: rows.length,
    OPEN: rows.filter((r) => r.status !== "CLOSED").length,
    CLOSED: rows.filter((r) => r.status === "CLOSED").length,
  }), [rows]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      const ok = filter === "all" ? true : filter === "CLOSED" ? r.status === "CLOSED" : r.status !== "CLOSED";
      if (!ok) return false;
      if (!needle) return true;
      return [r.case_id, r.title, r.investigator_id, r.attributed_recipient_id ?? ""]
        .some((v) => v.toLowerCase().includes(needle));
    });
  }, [rows, q, filter]);

  if (cases.loading && !cases.data) return <LoadingState label="Loading investigations" detail="GET /investigations" />;
  if (cases.error) {
    const st = (cases.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={cases.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={cases.error} onRetry={cases.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Investigations"
        sub="A case groups evidence, notes and a final verification status. Attribution always points at a session and a key holder, never at a person in the physical world."
        actions={
          <>
            <button className="btn primary" onClick={() => setNewOpen(true)}>+ Open case</button>
            <button className="btn" onClick={cases.reload} disabled={cases.loading}>
              {cases.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      <div className="grid g4">
        <Metric label="Total cases" value={counts.all} tone="info" />
        <Metric label="Open" value={counts.OPEN} tone={counts.OPEN ? "warn" : "ok"} sub="under investigation" />
        <Metric label="Closed" value={counts.CLOSED} tone="ok" sub="final status recorded" />
        <Metric
          label="Verified attribution"
          value={rows.filter((r) => r.final_verification_status === "VERIFIED_ASSOCIATION").length}
          tone="ok"
          sub="link to a session"
        />
      </div>

      <Panel flush>
        <div className="panel-body" style={{ borderBottom: "1px solid var(--hair)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <SearchInput value={q} onChange={setQ} placeholder="Search case, title, investigator, attribution…" width={340} />
          <FilterChips
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All", count: counts.all },
              { value: "OPEN", label: "Open", count: counts.OPEN },
              { value: "CLOSED", label: "Closed", count: counts.CLOSED },
            ]}
          />
          <span className="tiny dim" style={{ marginLeft: "auto" }}>{filtered.length} of {rows.length} shown</span>
        </div>

        <DataTable
          rows={filtered}
          onRow={(r) => setOpenId(r.case_id)}
          empty={<EmptyState icon="⚑" title="No cases" sub="Open a case from the Forensics console when you have a suspect copy to examine." />}
          columns={[
            { key: "t", head: "Title", render: (r) => (
              <span className="stack" style={{ gap: 2 }}>
                <span>{r.title}</span>
                <span className="tiny dim">by {r.investigator_id}</span>
              </span>
            ) },
            { key: "id", head: "Case ID", render: (r) => <IdentBadge id={r.case_id} kind="case" /> },
            { key: "e", head: "Evidence", num: true, render: (r) => r.evidence_count },
            { key: "v", head: "Verification", render: (r) => (
              r.final_verification_status
                ? <StatusBadge status={r.final_verification_status} />
                : <span className="dim tiny">in progress</span>
            ) },
            { key: "a", head: "Attributed to", render: (r) => <IdentBadge id={r.attributed_recipient_id} kind="recipient" /> },
            { key: "h", head: "Report hash", render: (r) => <Hash value={r.report_sha256} chars={12} /> },
            { key: "s", head: "Status", render: (r) => <StatusBadge status={r.status} /> },
          ]}
        />
      </Panel>

      {openId ? <CaseDrawer caseId={openId} onClose={() => setOpenId(null)} onDone={() => cases.reload()} /> : null}
      {newOpen ? <NewCase onClose={() => setNewOpen(false)} onDone={() => { cases.reload(); toast.success("Case opened"); }} /> : null}
    </div>
  );
}

/* ------------------------------------------------------------- drawer */

function CaseDrawer({ caseId, onClose, onDone }: {
  caseId: string; onClose: () => void; onDone: () => void;
}) {
  const toast = useToast();
  const detail = useAsync<Record<string, unknown>>(
    () => api.get<Record<string, unknown>>(endpoints.investigation(caseId)), [caseId],
  );
  const [noteOpen, setNoteOpen] = useState(false);
  const [closeOpen, setCloseOpen] = useState(false);

  const d = detail.data as Record<string, never> | null;
  const c = (d?.case ?? d) as Record<string, string> & {
    notes?: { note_id: string; investigator_id: string; note: string; created_at: string }[];
    evidence?: { evidence_id: string; outcome: string; created_at: string }[];
  } | null;

  return (
    <>
      <Drawer
        title={c?.title ?? "Investigation case"}
        sub={<IdentBadge id={caseId} kind="case" />}
        onClose={onClose}
        actions={
          <>
            <button className="btn sm" onClick={() => setNoteOpen(true)}>+ Note</button>
            <button className="btn sm warn" onClick={() => setCloseOpen(true)}>Close case</button>
          </>
        }
      >
        {detail.loading && !c ? <LoadingState label="Loading case record" /> : null}
        {detail.error ? <ErrorNotice error={detail.error} onRetry={detail.reload} /> : null}

        {c ? (
          <div className="stack">
            <div className="flex wrap gap-sm">
              <StatusBadge status={c.status} lg />
              {c.final_verification_status ? <StatusBadge status={c.final_verification_status} lg /> : null}
            </div>

            <Panel title="Case record">
              <dl className="kv">
                <dt>Case ID</dt><dd>{c.case_id}</dd>
                <dt>Investigator</dt><dd>{c.investigator_id}</dd>
                <dt>Opened</dt><dd>{c.created_at}</dd>
                <dt>Attributed recipient</dt><dd>{c.attributed_recipient_id ?? "—"}</dd>
                <dt>Verification</dt><dd>{c.final_verification_status ?? "in progress"}</dd>
                <dt>Report SHA-256</dt><dd><Hash value={c.report_sha256} chars={26} /></dd>
              </dl>
            </Panel>

            {c.evidence?.length ? (
              <Panel title="Evidence in case" flush>
                <DataTable
                  rows={c.evidence}
                  columns={[
                    { key: "i", head: "Evidence ID", render: (e) => <IdentBadge id={e.evidence_id} kind="evidence" /> },
                    { key: "o", head: "Outcome", render: (e) => <StatusBadge status={e.outcome} /> },
                    { key: "t", head: "Recorded", render: (e) => <span className="tiny dim">{e.created_at?.slice(0, 19).replace("T", " ")}</span> },
                  ]}
                />
              </Panel>
            ) : null}

            <Panel title="Investigator notes" flush>
              <Timeline
                items={(c.notes ?? []).map((n) => ({
                  id: n.note_id,
                  time: n.created_at,
                  title: n.investigator_id,
                  detail: n.note,
                }))}
              />
            </Panel>
          </div>
        ) : null}
      </Drawer>

      {noteOpen ? <AddNote caseId={caseId} onClose={() => setNoteOpen(false)} onDone={() => { detail.reload(); toast.success("Note recorded"); }} /> : null}
      {closeOpen ? (
        <CloseCase
          caseId={caseId}
          onClose={() => setCloseOpen(false)}
          onDone={() => { setCloseOpen(false); detail.reload(); onDone(); toast.success("Case closed", "The final verification status is now fixed for the record."); }}
        />
      ) : null}
    </>
  );
}

function AddNote({ caseId, onClose, onDone }: { caseId: string; onClose: () => void; onDone: () => void }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(endpoints.investigationNotes(caseId), { note });
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
      title="Add investigator note"
      sub={<IdentBadge id={caseId} kind="case" />}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={submit} disabled={busy || note.trim().length < 3}>
            {busy ? "Saving…" : "Record note"}
          </button>
        </>
      }
    >
      <Field label="Note" hint="written to the audit trail verbatim">
        <textarea className="inp" rows={4} value={note} onChange={(e) => setNote(e.target.value)} />
      </Field>
      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}

function CloseCase({ caseId, onClose, onDone }: { caseId: string; onClose: () => void; onDone: () => void }) {
  const [conclusion, setConclusion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(endpoints.investigationClose(caseId), { conclusion });
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Close investigation"
      sub={<IdentBadge id={caseId} kind="case" />}
      onClose={onClose}
      danger
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn warn" onClick={submit} disabled={busy || conclusion.trim().length < 5}>
            {busy ? "Closing…" : "Close case"}
          </button>
        </>
      }
    >
      <Notice tone="warn" title="The conclusion becomes part of the permanent record">
        State only what the evidence supports. An association proves a link to a session and key holder, not who was
        physically holding the device.
      </Notice>

      <div className="mt">
        <Field label="Conclusion" hint={`${conclusion.trim().length}/5 minimum`}>
          <textarea className="inp" rows={4} value={conclusion} onChange={(e) => setConclusion(e.target.value)}
            placeholder="Watermark recovered with 96% confidence and matched to session SES-… issued to RECIPIENT-002." />
        </Field>
      </div>

      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}

function NewCase({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [suspected, setSuspected] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(endpoints.investigations, {
        title,
        summary,
        suspected_document_id: suspected.trim() || null,
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
      title="Open investigation case"
      sub="A case scopes evidence, notes and the final verdict."
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={submit} disabled={busy || title.trim().length < 5}>
            {busy ? "Opening…" : "Open case"}
          </button>
        </>
      }
    >
      <Field label="Title">
        <input className="inp" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Suspect copy recovered from external share" />
      </Field>
      <Field label="Summary">
        <textarea className="inp" rows={3} value={summary} onChange={(e) => setSummary(e.target.value)}
          placeholder="What are you trying to establish?" />
      </Field>
      <Field label="Suspected document ID" hint="optional">
        <input className="inp" value={suspected} onChange={(e) => setSuspected(e.target.value)} placeholder="DOC-…" />
      </Field>
      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}
