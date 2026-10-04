import { useRef, useState } from "react";
import {
  api, endpoints,
  type ChainLink, type EvidenceReport, type ForensicAnalysis, type InvestigationRow,
} from "../api";
import {
  Badge, ErrorNotice, Field, Hash, LoadingState, Metric, Modal, Notice, PageHead, Panel,
  Pipeline, StatusBadge, Unauthorized, VerificationStep, useAsync, useToast,
} from "../components/ui";
import { IdentBadge } from "../components/layout";

export function Forensics() {
  const toast = useToast();
  const cases = useAsync<{ cases: InvestigationRow[] }>(() => api.get(endpoints.investigations), []);
  const [file, setFile] = useState<File | null>(null);
  const [caseId, setCaseId] = useState("");
  const [phase, setPhase] = useState<"idle" | "analyzing" | "verifying" | "reporting">("idle");
  const [analysis, setAnalysis] = useState<ForensicAnalysis | null>(null);
  const [report, setReport] = useState<EvidenceReport | null>(null);
  const [integrity, setIntegrity] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [exportOpen, setExportOpen] = useState(false);
  const [caseOpen, setCaseOpen] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const openCases = cases.data?.cases ?? [];

  const reset = () => {
    setAnalysis(null); setReport(null); setIntegrity(null); setError(null); setPhase("idle");
  };

  const analyze = async () => {
    if (!file || !caseId) return;
    reset();
    try {
      setPhase("analyzing");
      const form = new FormData();
      form.append("case_id", caseId);
      form.append("file", file);
      const body = await api.postForm<{ analysis: ForensicAnalysis }>(endpoints.forensicsAnalyze, form);
      setAnalysis(body.analysis);

      setPhase("verifying");
      const vf = new FormData();
      vf.append("case_id", body.analysis.case_id);
      vf.append("evidence_id", body.analysis.evidence_id);
      await api.postForm(endpoints.forensicsVerify, vf);

      setPhase("reporting");
      const rep = await api.post<{ report: EvidenceReport }>(endpoints.evidenceReport(body.analysis.evidence_id), {});
      setReport(rep.report);

      const check = await api.get<Record<string, unknown>>(endpoints.evidenceIntegrity(body.analysis.evidence_id));
      setIntegrity(check);
      setPhase("idle");
      toast.success("Verification complete", `Evidence ${body.analysis.evidence_id} sealed and hashed.`);
    } catch (e) {
      setError(e);
      setPhase("idle");
      toast.failure("Verification halted", String((e as Error).message));
    }
  };

  const busy = phase !== "idle";

  if (report && analysis) {
    return (
      <div className="stack">
        <PageHead
          title="Forensic Verification"
          sub="A suspect copy was analysed against sealed evidence. Everything below is what the backend actually returned."
          actions={
            <>
              <Badge tone={analysis.outcome === "VERIFIED_ASSOCIATION" ? "ok" : "warn"} lg>{analysis.outcome}</Badge>
              <button className="btn" onClick={() => setExportOpen(true)}>⇩ Export evidence bundle</button>
              <button className="btn primary" onClick={() => { reset(); setFile(null); if (fileInput.current) fileInput.current.value = ""; }}>
                + Verify another copy
              </button>
            </>
          }
        />
        <EvidenceView analysis={analysis} report={report} integrity={integrity} />
      </div>
    );
  }

  return (
    <div className="stack">
      <PageHead
        title="Forensic Verification"
        sub="Upload a document found outside the system. The pipeline extracts the watermark, verifies the evidence chain and seals the result."
        actions={<Badge tone="info">3-STAGE PIPELINE</Badge>}
      />

      {error ? <ErrorNotice error={error} /> : null}

      <div className="grid g3">
        <Panel title="1 · Evidence intake" actions={<Badge tone={file ? "ok" : "idle"}>{file ? "READY" : "EMPTY"}</Badge>}>
          <div
            onClick={() => fileInput.current?.click()}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => { e.preventDefault(); setFile(e.dataTransfer.files?.[0] ?? null); }}
            style={{
              border: `1px dashed ${file ? "var(--ok-line)" : "var(--line-2)"}`,
              background: file ? "var(--ok-bg)" : "var(--bg-2)",
              borderRadius: "var(--radius)",
              padding: "22px 14px",
              textAlign: "center",
              cursor: "pointer",
              transition: "border-color 130ms ease, background 130ms ease",
            }}
          >
            <div style={{ fontSize: 20, opacity: 0.5 }} aria-hidden>⇪</div>
            <div style={{ marginTop: 6, fontSize: 12 }}>
              {file ? file.name : "Drop a suspect copy here"}
            </div>
            <div className="tiny dim" style={{ marginTop: 3 }}>
              {file ? `${file.size.toLocaleString()} bytes · ${file.type || "unknown type"}` : "or click to browse"}
            </div>
            <input
              ref={fileInput}
              type="file"
              style={{ display: "none" }}
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              aria-label="Suspect document"
            />
          </div>

          <div className="mt">
            <Field label="Investigation case" hint="required by the backend">
              {cases.loading ? <LoadingState label="Loading cases" /> : openCases.length === 0 ? (
                <div className="notice warn">
                  <span className="ico" aria-hidden>▲</span>
                  <div style={{ flex: 1 }}>
                    <b>No open case</b>
                    <div>The backend refuses analysis without a case, because evidence must be scoped before it is sealed.</div>
                  </div>
                  <button className="btn sm" onClick={() => setCaseOpen(true)}>Open case</button>
                </div>
              ) : (
                <select className="inp" value={caseId} onChange={(e) => setCaseId(e.target.value)} disabled={busy}>
                  <option value="">Select a case…</option>
                  {openCases.map((c: InvestigationRow) => (
                    <option key={c.case_id} value={c.case_id}>
                      {c.case_id} — {c.title} ({c.evidence_count} evidence)
                    </option>
                  ))}
                </select>
              )}
            </Field>
            <button className="btn primary block" onClick={analyze} disabled={!file || !caseId || busy}>
              {busy ? phase.toUpperCase() : "▶ Run verification"}
            </button>
            {openCases.length > 0 ? (
              <button className="btn ghost block" style={{ marginTop: 6 }} onClick={() => setCaseOpen(true)} disabled={busy}>
                + Open another case
              </button>
            ) : null}
          </div>
        </Panel>

        <Panel title="2 · Watermark extraction" actions={phase === "verifying" ? <Badge tone="info">RUNNING</Badge> : null}>
          <ol className="stack" style={{ gap: 10, paddingLeft: 18, margin: 0 }}>
            <li className="tiny muted">Content hash computed with SHA-256 and compared against every sealed version.</li>
            <li className="tiny muted">DCT watermark carriers extracted across the mid-frequency band.</li>
            <li className="tiny muted">Tag decoded, keyed against each candidate session, scored by bit error rate.</li>
            <li className="tiny muted">Chain links verified: signature, event hash, ledger inclusion, device binding.</li>
          </ol>
          <div className="hr" />
          <div className="tiny dim">
            Every stage runs server-side against real crypto. The console performs no extraction of its own and shows
            no confidence figure until the backend returns one.
          </div>
        </Panel>

        <Panel title="3 · Sealed outcome" actions={phase === "reporting" ? <Badge tone="info">SEALING</Badge> : null}>
          <div className="stack" style={{ gap: 9 }}>
            <PipelineStep n="A" title="Evidence chain" done={false} active={phase !== "idle"} />
            <PipelineStep n="B" title="Report hash (SHA-256)" done={false} active={phase === "reporting"} />
            <PipelineStep n="C" title="Ledger transaction" done={false} active={phase === "reporting"} />
          </div>
          <div className="hr" />
          <div className="tiny dim">
            The outcome is only reported as verified when the watermark, the signature and the ledger anchor all agree.
          </div>
        </Panel>
      </div>

      <Panel title="What this console does not claim">
        <div className="grid g2">
          <Notice tone="warn" title="Association, not proof of identity">
            A recovered tag proves the copy came from a specific decryption session of a specific recipient. It does
            not prove who was physically holding the device.
          </Notice>
          <Notice tone="warn" title="Only declared transformations">
            The extractor survives the transformations measured in the Watermark Probe. Heavier re-encoding or
            re-shooting may destroy the carriers, and the console will report that honestly.
          </Notice>
        </div>
      </Panel>

      {exportOpen ? (
        <ExportBundle
          defaultCaseId={analysis?.case_id ?? caseId}
          onClose={() => setExportOpen(false)}
        />
      ) : null}
      {caseOpen ? (
        <QuickCase
          onClose={() => setCaseOpen(false)}
          onOpened={(id) => { setCaseId(id); cases.reload(); }}
        />
      ) : null}
    </div>
  );
}

function PipelineStep({ n, title, done, active }: { n: string; title: string; done: boolean; active: boolean }) {
  return (
    <div className="flex gap-sm">
      <span className={`mark ${done ? "ok" : active ? "info" : ""}`}
        style={{
          width: 20, height: 20, borderRadius: "50%", display: "grid", placeItems: "center",
          fontFamily: "var(--mono)", fontSize: 10,
          border: `1px solid ${done ? "var(--ok-line)" : active ? "var(--info-line)" : "var(--line)"}`,
          background: done ? "var(--ok-bg)" : active ? "var(--info-bg)" : "var(--bg-2)",
          color: done ? "var(--ok)" : active ? "var(--info)" : "var(--dim)",
        }}
      >
        {done ? "✓" : n}
      </span>
      <span style={{ fontSize: 11.5 }}>{title}</span>
    </div>
  );
}

/* -------------------------------------------------------- evidence view */

function EvidenceView({ analysis, report, integrity }: {
  analysis: ForensicAnalysis; report: EvidenceReport; integrity: Record<string, unknown> | null;
}) {
  const verified = analysis.outcome === "VERIFIED_ASSOCIATION";
  const confidence = Math.round(analysis.watermark.confidence * 100);

  return (
    <div className="stack">
      <div className={`evidence ${verified ? "" : "warn"}`}>
        <div className="flex-between wrap">
          <div style={{ minWidth: 0 }}>
            <h2>{analysis.outcome}</h2>
            <div className="sub">{analysis.outcome_explanation}</div>
          </div>
          <StatusBadge status={analysis.watermark.status} lg />
        </div>

        <div className="confidence-ring">
          <b style={{ color: confidence >= 90 ? "var(--ok)" : confidence >= 60 ? "var(--warn)" : "var(--crit)" }}>
            {confidence}%
          </b>
          <span>watermark confidence · CNR {analysis.watermark.carrier_to_noise_ratio.toFixed(2)} · {analysis.watermark.estimated_bit_errors} bit errors</span>
        </div>
        <div className="bar"><i className={confidence >= 90 ? "ok" : "warn"} style={{ width: `${Math.max(2, confidence)}%` }} /></div>
      </div>

      <div className="grid g6">
        <Metric label="Evidence ID" small value={<IdentBadge id={analysis.evidence_id} kind="evidence" />} sub="immutable chain anchor" />
        <Metric label="Case" small value={<IdentBadge id={analysis.case_id} kind="case" />} sub="investigation scope" />
        <Metric label="Matched session" small value={<IdentBadge id={analysis.matched_session_id} kind="session" />} sub="exact decryption event" />
        <Metric label="Matched recipient" small value={<IdentBadge id={analysis.matched_recipient_id} kind="recipient" />} sub="key holder" />
        <Metric label="Matched document" small value={<IdentBadge id={analysis.matched_document_id} />} sub="sealed original" />
        <Metric label="Matched version" small value={<IdentBadge id={analysis.matched_version_id} kind="version" />} sub={`version ${analysis.matched_version_id ? "" : "—"}`} />
      </div>

      <div className="grid g-1-2">
        <Panel title="Chain integrity" flush>
          <Pipeline>
            {analysis.evidence_chain.map((link: ChainLink) => (
              <VerificationStep
                key={link.link}
                state={link.status === "PASS" ? "pass" : link.status === "FAIL" ? "fail" : link.status === "PARTIAL" ? "partial" : "unknown"}
                name={link.link.replace(/_/g, " ")}
                detail={link.detail}
              />
            ))}
          </Pipeline>
          <div className="panel-body" style={{ borderTop: "1px solid var(--hair)" }}>
            <div className="flex-between tiny">
              <span className="muted">Chain summary</span>
              <span className="mono">
                {analysis.chain_summary.links_passed}/{analysis.chain_summary.links_total} passed
                {analysis.chain_summary.links_partial ? ` · ${analysis.chain_summary.links_partial} partial` : ""}
                {analysis.chain_summary.links_failed ? ` · ${analysis.chain_summary.links_failed} failed` : ""}
              </span>
            </div>
          </div>
        </Panel>

        <div className="stack">
          <Panel title="Sealed report">
            <dl className="kv">
              <dt>Report SHA-256</dt><dd><Hash value={report.report_sha256} chars={30} /></dd>
              <dt>Content SHA-256</dt><dd><Hash value={analysis.content_sha256} chars={30} /></dd>
              <dt>Generated at</dt><dd>{report.generated_at}</dd>
              <dt>Watermark tag</dt><dd><Hash value={report.watermark.recovered_tag} chars={24} /></dd>
            </dl>
          </Panel>

          <Panel title="Report integrity re-check" actions={integrity ? <Badge tone="ok">RE-VERIFIED</Badge> : null}>
            {integrity ? (
              <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap", color: "var(--tx-2)" }}>
                {JSON.stringify(integrity, null, 2)}
              </pre>
            ) : <LoadingState label="Re-checking report hash" />}
            <div className="tiny dim" style={{ marginTop: 7 }}>
              A report is only evidence if its hash still matches later. This panel recomputes it on demand.
            </div>
          </Panel>
        </div>
      </div>

      <Panel title="Declared limitations" tone="warn">
        <ul className="stack" style={{ gap: 5, paddingLeft: 18, margin: 0 }}>
          {analysis.limitations.map((l) => <li key={l} className="tiny muted">{l}</li>)}
        </ul>
      </Panel>
    </div>
  );
}

/* ------------------------------------------------------------- export */

function ExportBundle({ defaultCaseId, onClose }: { defaultCaseId: string; onClose: () => void }) {
  const toast = useToast();
  const [caseId, setCaseId] = useState(defaultCaseId);
  const [approvalId, setApprovalId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const body = await api.post<Record<string, unknown>>(endpoints.evidenceExport, { case_id: caseId, approval_id: approvalId });
      toast.success("Evidence bundle exported", JSON.stringify(body).slice(0, 160));
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Export evidence bundle"
      sub="Exporting evidence is itself a controlled action — the backend requires an approval ID."
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={run} disabled={busy || !caseId || !approvalId}>
            {busy ? "Exporting…" : "⇩ Export"}
          </button>
        </>
      }
    >
      <Field label="Case ID">
        <input className="inp" value={caseId} onChange={(e) => setCaseId(e.target.value)} />
      </Field>
      <Field label="Approval ID" hint="from the Approvals console">
        <input className="inp" value={approvalId} onChange={(e) => setApprovalId(e.target.value)} placeholder="APR-…" />
      </Field>
      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}

/* ----------------------------------------------------------- quick case */

function QuickCase({ onClose, onOpened }: { onClose: () => void; onOpened: (caseId: string) => void }) {
  const toast = useToast();
  const [title, setTitle] = useState("Suspect copy recovered from external share");
  const [summary, setSummary] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const body = await api.post<{ case: { case_id: string } }>(endpoints.investigations, { title, summary });
      toast.success("Case opened", body.case.case_id);
      onOpened(body.case.case_id);
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
      sub="Evidence cannot be sealed without a case scope."
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={submit} disabled={busy || title.trim().length < 3}>
            {busy ? "Opening…" : "Open case"}
          </button>
        </>
      }
    >
      <Field label="Title">
        <input className="inp" value={title} onChange={(e) => setTitle(e.target.value)} />
      </Field>
      <Field label="Summary">
        <textarea className="inp" rows={3} value={summary} onChange={(e) => setSummary(e.target.value)} />
      </Field>
      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}
