import { useCallback, useEffect, useState } from "react";
import {
  api, endpoints,
  type AuditDenial, type Dashboard, type ForensicAnalysis, type Kpi, type LedgerVerification,
  type LockdownState, type RevocationRow, type RiskWatchRow,
} from "../api";
import {
  Badge, CopyButton, DataTable, Dot, EmptyState, ErrorNotice, Hash, LoadingState, Metric,
  Notice, Panel, PageHead, Pipeline, StatusBadge, Timeline, Unauthorized,
  VerificationStep, useAsync, useToast, type StepState,
} from "../components/ui";
import { IdentBadge } from "../components/layout";

export function CommandCenter({ permissions, onNavigate, onLockdownChanged }: {
  permissions: string[];
  onNavigate: (id: string) => void;
  onLockdownChanged: () => void;
}) {
  const toast = useToast();
  const dash = useAsync<Dashboard>(() => api.get<Dashboard>(endpoints.commander), []);
  const lockdown = useAsync<LockdownState>(() => api.get<LockdownState>(endpoints.lockdown), []);

  const [locking, setLocking] = useState(false);

  const toggleLockdown = async () => {
    const active = lockdown.data?.lockdown_active ?? false;
    const reason = active ? "Lockdown released by the commander" : window.prompt(
      "Lockdown reason (recorded in the audit trail and shown to every operator):",
      "Commander-initiated emergency containment",
    );
    if (!active && reason === null) return;
    if (active && !window.confirm("Release the emergency lockdown? Decryption authorisation resumes immediately.")) return;

    setLocking(true);
    try {
      if (active) {
        // Lifting a lockdown needs two signatures from identities that did not raise
        // it, so the button raises the request rather than firing an unlock that
        // the backend will always refuse.
        const raised = await api.post<{ approval_id: string }>(endpoints.approvals, {
          action: "EMERGENCY_ACCESS",
          justification: reason,
          required_approvals: 2,
        });
        toast.success(
          `Release request ${raised.approval_id} raised`,
          "Two approvers must sign before decryption resumes. The requester cannot approve it.",
        );
      } else {
        await api.post(endpoints.lockdown, { reason });
        toast.success("Emergency lockdown engaged", "The backend confirmed the new state.");
      }
      lockdown.reload();
      onLockdownChanged();
    } catch (e) {
      toast.failure("Lockdown request refused", String((e as Error).message));
    } finally {
      setLocking(false);
    }
  };

  if (dash.loading && !dash.data) return <LoadingState label="Establishing command view" detail="GET /commander/dashboard" />;
  if (dash.error) {
    const st = (dash.error as { status?: number }).status;
    return st === 403
      ? <Unauthorized error={dash.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={dash.error} onRetry={dash.reload} />;
  }
  if (!dash.data) return <EmptyState title="No dashboard payload" sub="The backend returned an empty body." />;

  const d = dash.data;
  const isLocked = lockdown.data?.lockdown_active ?? false;

  return (
    <div className="stack">
      <PageHead
        title="Command Centre"
        sub="Live operational picture: posture, live detection events, ledger agreement and the forensic verification pipeline."
        actions={
          <>
            <Badge tone="info">CRYPTOGRAPHICALLY VERIFIABLE ASSOCIATION</Badge>
            <button className="btn" onClick={dash.reload} disabled={dash.loading}>
              {dash.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
            <button className="btn" onClick={onNavigate.bind(null, "lab")}>⚗ Security Lab</button>
            <button className="btn" onClick={onNavigate.bind(null, "investigations")}>⚑ Investigations</button>
            <button
              className={`btn ${isLocked ? "primary" : "danger"}`}
              onClick={toggleLockdown}
              disabled={locking}
            >
              {locking ? "Working…" : isLocked ? "⏻ Request release" : "⚑ Engage lockdown"}
            </button>
          </>
        }
      />

      <MetricRow kpi={d.kpis} onNavigate={onNavigate} />

      {isLocked ? (
        <Notice tone="crit" title="Emergency lockdown is active">
          The backend refuses every decryption authorisation request. Release it from the action above once the
          containment criteria are met.
        </Notice>
      ) : null}

      <div className="grid g-2-1">
        <PosturePanel dashboard={d} />
        <LiveFeed dashboard={d} onNavigate={onNavigate} />
      </div>

      <div className="grid g-3-2">
        <RecentDecryptions dashboard={d} onNavigate={onNavigate} />
        <LedgerAgreement mayVerify={permissions.includes("ledger.verify")} />
      </div>

      <OperationalFeed dashboard={d} onNavigate={onNavigate} />

      <ForensicPipeline onNavigate={onNavigate} mayAnalyze={permissions.includes("forensics.analyze")} />

      <TopologyStrip topology={d.topology} />

      <HonestyFooter statement={d.attribution_statement} />
    </div>
  );
}

/* --------------------------------------------------------------- metrics */

function MetricRow({ kpi, onNavigate }: { kpi: Kpi; onNavigate: (id: string) => void }) {
  return (
    <div className="grid g6">
      <Metric
        label="Documents protected" value={kpi.documents_protected}
        sub="sealed under post-quantum keys" tone="info"
        foot={<Badge tone="idle">PQC SEALED</Badge>}
      />
      <Metric
        label="Active recipients" value={kpi.active_recipients}
        sub={`${kpi.revoked_recipients} revoked`} tone="ok"
        foot={<button className="btn sm ghost" onClick={() => onNavigate("recipients")}>View</button>}
      />
      <Metric
        label="Registered devices" value={kpi.registered_devices}
        sub={`${kpi.revoked_devices} revoked`} tone={kpi.revoked_devices ? "warn" : "ok"}
        foot={<button className="btn sm ghost" onClick={() => onNavigate("devices")}>View</button>}
      />
      <Metric
        label="Active sessions" value={kpi.active_sessions}
        sub="decryptions in flight" tone="info"
        foot={<button className="btn sm ghost" onClick={() => onNavigate("sessions")}>View</button>}
      />
      <Metric
        label="Open events" value={kpi.security_events_open}
        sub={`${kpi.critical_incidents} critical · ${kpi.high_incidents} high`}
        tone={kpi.critical_incidents ? "crit" : kpi.security_events_open ? "warn" : "ok"}
        foot={<button className="btn sm ghost" onClick={() => onNavigate("events")}>Review</button>}
      />
      <Metric
        label="Watermarks issued" value={kpi.watermarks_issued}
        sub={`${kpi.verified_evidence} verified · ${kpi.open_investigations} open cases`}
        tone="ok"
        foot={<button className="btn sm ghost" onClick={() => onNavigate("forensics")}>Verify</button>}
      />
    </div>
  );
}

/* --------------------------------------------------------------- posture */

function PosturePanel({ dashboard }: { dashboard: Dashboard }) {
  const p = dashboard.security_posture;
  const tone = p.score >= 90 ? "ok" : p.score >= 70 ? "warn" : "crit";

  return (
    <Panel
      title="Security posture"
      actions={<Badge tone={tone}>{p.rating}</Badge>}
    >
      <div className="posture-score">
        <span className="num" style={{ color: `var(--${tone})` }}>
          {p.score}<small>/100</small>
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="bar"><i className={tone} style={{ width: `${Math.max(2, p.score)}%` }} /></div>
          <div className="tiny muted" style={{ marginTop: 6 }}>{p.basis}</div>
        </div>
      </div>

      <div className="checks">
        {p.factors.map((f) => (
          <div className="check-row" key={f.factor}>
            <Dot tone={f.value >= 90 ? "ok" : f.value >= 70 ? "warn" : "crit"} />
            <div style={{ minWidth: 0 }}>
              <div className="nm">{f.factor}</div>
              <div className="ex">{f.detail}</div>
            </div>
            <div className="vl" style={{ color: `var(--${f.value >= 90 ? "ok" : f.value >= 70 ? "warn" : "crit"})` }}>
              {f.value}
            </div>
          </div>
        ))}
      </div>

      <div className="hr" />
      <div className="tiny dim">{p.disclaimer}</div>
    </Panel>
  );
}

/* ------------------------------------------------------------- live feed */

function LiveFeed({ dashboard, onNavigate }: { dashboard: Dashboard; onNavigate: (id: string) => void }) {
  const events = dashboard.live_security_events ?? [];

  return (
    <Panel
      title="Live security events"
      actions={<Badge tone={events.length ? "warn" : "ok"}>{events.length} OPEN</Badge>}
      flush
    >
      <div style={{ maxHeight: 384, overflowY: "auto" }}>
        <Timeline
          items={events.slice(0, 12).map((e) => ({
            id: e.security_event_id,
            time: e.detected_at,
            title: e.title,
            severity: e.severity,
            detail: e.plain_explanation,
            right: <StatusBadge status={e.status} />,
          }))}
        />
      </div>
      <div className="panel-body" style={{ borderTop: "1px solid var(--hair)" }}>
        <button className="btn block" onClick={() => onNavigate("events")}>Open security event queue →</button>
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------- recent decrypt */

function RecentDecryptions({ dashboard, onNavigate }: { dashboard: Dashboard; onNavigate: (id: string) => void }) {
  const rows = dashboard.recent_decryptions ?? [];
  return (
    <Panel
      title="Recent decryptions"
      actions={<button className="btn sm" onClick={() => onNavigate("sessions")}>All sessions</button>}
      flush
    >
      <DataTable
        rows={rows}
        empty={<EmptyState icon="⊛" title="No decryption sessions yet" sub="Sessions appear here the moment an authorised recipient opens a protected document." />}
        onRow={(r) => onNavigate("sessions")}
        columns={[
          { key: "s", head: "Session", render: (r) => <Hash value={r.session_id} chars={18} /> },
          { key: "r", head: "Recipient", render: (r) => <span className="mono">{r.recipient_id}</span> },
          { key: "v", head: "Ver", num: true, render: (r) => r.version_number },
          {
            key: "st", head: "Status", render: (r) => (
              <span className="flex gap-sm">
                <StatusBadge status={r.status} />
                {r.break_glass ? <Badge tone="crit">BREAK-GLASS</Badge> : null}
              </span>
            ),
          },
          { key: "t", head: "Issued", render: (r) => <span className="tiny dim">{r.issued_at?.slice(11, 19) ?? "—"}</span> },
        ]}
      />
    </Panel>
  );
}

/* ------------------------------------------- denials / revocations / watchlist */

function OperationalFeed({ dashboard, onNavigate }: { dashboard: Dashboard; onNavigate: (id: string) => void }) {
  return (
    <div className="grid g3">
      <RiskWatchlist rows={dashboard.risk_watchlist ?? []} onNavigate={onNavigate} />
      <PolicyDenials rows={dashboard.recent_policy_denials ?? []} total={dashboard.kpis.policy_denials ?? 0} onNavigate={onNavigate} />
      <RevocationsFeed rows={dashboard.recent_revocations ?? []} total={dashboard.kpis.revocations_recorded ?? 0} onNavigate={onNavigate} />
    </div>
  );
}

function riskTone(level: string): "crit" | "high" | "warn" | "ok" {
  if (level === "CRITICAL") return "crit";
  if (level === "HIGH") return "high";
  if (level === "MEDIUM") return "warn";
  return "ok";
}

function RiskWatchlist({ rows, onNavigate }: { rows: RiskWatchRow[]; onNavigate: (id: string) => void }) {
  const elevated = rows.some((r) => r.risk_level === "HIGH" || r.risk_level === "CRITICAL");
  return (
    <Panel title="Risk watchlist" actions={<Badge tone={elevated ? "crit" : "ok"}>{rows.length} TRACKED</Badge>} flush>
      <DataTable
        rows={rows}
        empty={<EmptyState icon="✓" title="No elevated identities" sub="Nobody currently carries a risk score worth flagging." />}
        columns={[
          { key: "r", head: "Recipient", render: (r) => <IdentBadge id={r.recipient_id} kind="recipient" /> },
          { key: "l", head: "Level", render: (r) => <Badge tone={riskTone(r.risk_level)}>{r.risk_level}</Badge> },
          { key: "s", head: "Score", num: true, render: (r) => (
            <b style={{ color: `var(--${riskTone(r.risk_level)})` }}>{r.risk_score}</b>
          ) },
          { key: "f", head: "Why", render: (r) => (
            <span className="tiny dim">{r.top_factors?.map((f) => f.replace(/_/g, " ")).join(" · ") ?? "no factors"}</span>
          ) },
        ]}
      />
      <div className="panel-body" style={{ borderTop: "1px solid var(--hair)" }}>
        <button className="btn block" onClick={() => onNavigate("security")}>Open risk console →</button>
      </div>
    </Panel>
  );
}

function PolicyDenials({ rows, total, onNavigate }: {
  rows: AuditDenial[]; total: number; onNavigate: (id: string) => void;
}) {
  return (
    <Panel title="Policy refusals" actions={<Badge tone={total ? "warn" : "ok"}>{total} TOTAL</Badge>} flush>
      <DataTable
        rows={rows}
        empty={<EmptyState icon="✓" title="No denials recorded" sub="Every decryption request so far was authorised." />}
        columns={[
          { key: "a", head: "Actor", render: (r) => <span className="mono">{r.actor_id}</span> },
          { key: "d", head: "Document", render: (r) => <span className="mono tiny">{r.document_id ?? "—"}</span> },
          { key: "r", head: "Reason", render: (r) => <span className="tiny muted">{r.reason ?? "—"}</span> },
          { key: "t", head: "At (UTC)", render: (r) => <span className="tiny dim">{r.occurred_at?.slice(11, 19) ?? "—"}</span> },
        ]}
      />
      <div className="panel-body" style={{ borderTop: "1px solid var(--hair)" }}>
        <button className="btn block" onClick={() => onNavigate("security")}>Review in security console →</button>
      </div>
    </Panel>
  );
}

function RevocationsFeed({ rows, total, onNavigate }: { rows: RevocationRow[]; total: number; onNavigate: (id: string) => void }) {
  return (
    <Panel title="Recent revocations" actions={<Badge tone={total ? "warn" : "ok"}>{total} TOTAL</Badge>} flush>
      <DataTable
        rows={rows}
        empty={<EmptyState icon="✓" title="Nothing withdrawn" sub="No access has been revoked recently." />}
        columns={[
          { key: "s", head: "Subject", render: (r) => <IdentBadge id={r.subject_id} kind={r.subject_type?.toLowerCase()} /> },
          { key: "t", head: "Type", render: (r) => <span className="tiny dim">{r.subject_type}</span> },
          { key: "sc", head: "Scope", render: (r) => <Badge tone="crit">{r.scope}</Badge> },
          { key: "r", head: "Reason", render: (r) => <span className="tiny muted">{r.reason}</span> },
          { key: "at", head: "At (UTC)", render: (r) => <span className="tiny dim">{r.revoked_at?.slice(11, 19) ?? "—"}</span> },
        ]}
      />
      <div className="panel-body" style={{ borderTop: "1px solid var(--hair)" }}>
        <button className="btn block" onClick={() => onNavigate("oversight")}>Open revocation register →</button>
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------- ledger agreement */

function LedgerAgreement({ mayVerify }: { mayVerify: boolean }) {
  const [verify, setVerify] = useState<LedgerVerification | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  const run = useCallback(async () => {
    if (!mayVerify) return;
    setBusy(true);
    setErr(null);
    try {
      setVerify(await api.get<LedgerVerification>(endpoints.ledgerVerify));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }, [mayVerify]);

  useEffect(() => { run(); }, [run]);

  if (!mayVerify) {
    return (
      <Panel title="Ledger verification">
        <Notice tone="idle" title="Attestation reserved by separation of duties">
          Independent chain verification is held by AUDITOR, LEDGER_OPERATOR and INVESTIGATOR
          identities. Your role reads the ledger agreement reported in Security posture, but
          cannot attest to the chain itself.
        </Notice>
      </Panel>
    );
  }

  return (
    <Panel
      title="Ledger verification"
      actions={
        <button className="btn sm" onClick={run} disabled={busy}>{busy ? "Verifying…" : "↻ Re-verify"}</button>
      }
    >
      {err ? <ErrorNotice error={err} onRetry={run} /> : null}
      {!verify && !err ? <LoadingState label="Verifying chain" /> : null}

      {verify ? (
        <>
          <div className="flex-between mb">
            <StatusBadge status={verify.headline} lg />
            <Badge tone={verify.agreement.divergent.length ? "crit" : "ok"}>
              HEIGHT {verify.agreement.agreed_height}
            </Badge>
          </div>

          <Pipeline>
            {verify.nodes.map((n) => {
              const state: StepState = n.first_failing_height !== null ? "fail"
                : n.status === "VERIFIED" ? "pass" : "partial";
              return (
                <VerificationStep
                  key={n.node_id}
                  state={state}
                  name={n.node_id}
                  detail={`${n.blocks_checked} blocks · ${n.transactions_checked} transactions verified${n.first_failing_height !== null ? ` · first divergence at height ${n.first_failing_height}` : ""}`}
                  right={<StatusBadge status={n.status} />}
                />
              );
            })}
            <VerificationStep
              state={verify.agreement.divergent.length ? "fail" : "pass"}
              name="Cross-node state-root agreement"
              detail={verify.agreement.plain_explanation}
              right={<Hash value={verify.agreement.state_root} chars={12} />}
            />
          </Pipeline>

          {verify.nodes.some((n) => n.failures.length) ? (
            <div className="mt">
              <Notice tone="crit" title="Verification failures reported">
                {verify.nodes.flatMap((n) => n.failures.map((f) => `${n.node_id} · height ${f.height} · ${f.check}`)).join(" · ")}
              </Notice>
            </div>
          ) : null}
        </>
      ) : null}
    </Panel>
  );
}

/* ----------------------------------------------------- forensic pipeline */

function ForensicPipeline({ onNavigate, mayAnalyze }: {
  onNavigate: (id: string) => void;
  mayAnalyze: boolean;
}) {
  const toast = useToast();
  const [file, setFile] = useState<File | null>(null);
  const [caseId, setCaseId] = useState("");
  const [phase, setPhase] = useState<"idle" | "uploading" | "verifying" | "reporting" | "done">("idle");
  const [result, setResult] = useState<ForensicAnalysis | null>(null);
  const [err, setErr] = useState<unknown>(null);

  const runPipeline = async () => {
    if (!file) return;
    setErr(null);
    setResult(null);
    try {
      setPhase("uploading");

      // The backend scopes evidence to an investigation case and refuses analysis
      // without one, so an empty field means "open a case for this artefact".
      let target = caseId.trim();
      if (!target) {
        const opened = await api.post<{ case: { case_id: string } }>(endpoints.investigations, {
          title: `Command centre triage — ${file.name}`,
          summary: "Case opened automatically from the command centre forensic pipeline.",
        });
        target = opened.case.case_id;
      }

      const form = new FormData();
      form.append("case_id", target);
      form.append("file", file);
      const analysed = await api.postForm<{ analysis: ForensicAnalysis }>(endpoints.forensicsAnalyze, form);
      setResult(analysed.analysis);

      setPhase("verifying");
      const verifyForm = new FormData();
      verifyForm.append("case_id", analysed.analysis.case_id);
      verifyForm.append("evidence_id", analysed.analysis.evidence_id);
      await api.postForm(endpoints.forensicsVerify, verifyForm);

      setPhase("reporting");
      await api.post(endpoints.evidenceReport(analysed.analysis.evidence_id), {});
      setPhase("done");
      toast.success("Verification pipeline complete", `Evidence ${analysed.analysis.evidence_id} sealed and reported.`);
    } catch (e) {
      setErr(e);
      setPhase("idle");
      toast.failure("Pipeline halted", String((e as Error).message));
    }
  };

  const busy = phase !== "idle" && phase !== "done";

  if (!mayAnalyze) {
    return (
      <Panel
        title="Forensic verification pipeline"
        actions={
          <button className="btn sm" onClick={() => onNavigate("forensics")}>Full console →</button>
        }
      >
        <Notice tone="idle" title="Analysis reserved for investigator identities">
          Recovering a watermark, sealing it as evidence and opening a case are held by
          INVESTIGATOR identities, so the identity that orders the analysis can never be the one
          that attests to its result. Hand the artefact to the forensics console.
        </Notice>
      </Panel>
    );
  }

  return (
    <Panel
      title="Forensic verification pipeline"
      actions={
        <span className="flex gap-sm">
          {phase !== "idle" ? <Badge tone="info">{phase.toUpperCase()}</Badge> : null}
          <button className="btn sm" onClick={() => onNavigate("forensics")}>Full console →</button>
        </span>
      }
    >
      <div className="grid g3">
        <PipelineStep
          n={1} label="Upload suspect copy"
          state={phase === "idle" ? "unknown" : "pass"}
          detail="A document found outside the system. The original stays sealed."
          right={phase === "uploading" ? <Badge tone="info">UPLOADING</Badge> : null}
        >
          <input
            type="file"
            className="inp"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            disabled={busy}
            aria-label="Suspect document"
          />
          <div className="tiny dim" style={{ marginTop: 5 }}>
            {file ? `${file.name} · ${file.size.toLocaleString()} bytes` : "No file selected."}
          </div>
          <input
            className="inp"
            style={{ marginTop: 8 }}
            placeholder="Case ID (blank opens a triage case)"
            value={caseId}
            onChange={(e) => setCaseId(e.target.value)}
            disabled={busy}
            aria-label="Case ID"
          />
          <button
            className="btn primary block"
            style={{ marginTop: 9 }}
            disabled={!file || busy}
            onClick={runPipeline}
          >
            {busy ? "Running pipeline…" : "▶ Run verification pipeline"}
          </button>
        </PipelineStep>

        <PipelineStep
          n={2} label="Recover watermark & verify chain"
          state={result ? "pass" : "unknown"}
          detail="Extraction, hash match, signature verification and ledger lookup."
          right={result ? <Badge tone="ok">CONFIRMED</Badge> : null}
        >
          {result ? (
            <div className="stack" style={{ gap: 8 }}>
              <div className="flex-between">
                <span className="tiny muted">Watermark</span>
                <StatusBadge status={result.watermark.status} />
              </div>
              <div className="flex-between">
                <span className="tiny muted">Confidence</span>
                <span className="mono">{(result.watermark.confidence * 100).toFixed(1)}%</span>
              </div>
              <div className="flex-between">
                <span className="tiny muted">Chain links</span>
                <span className="mono">
                  {result.chain_summary.links_passed}/{result.chain_summary.links_total} passed
                </span>
              </div>
              <div className="flex-between">
                <span className="tiny muted">Matched session</span>
                <Hash value={result.matched_session_id} chars={12} />
              </div>
              <div className="bar"><i className="ok" style={{ width: `${Math.round(result.watermark.confidence * 100)}%` }} /></div>
            </div>
          ) : (
            <div className="tiny dim">Runs the real DCT watermark extractor against the uploaded copy.</div>
          )}
        </PipelineStep>

        <PipelineStep
          n={3} label="Seal evidence & issue report"
          state={phase === "done" ? "pass" : result ? "partial" : "unknown"}
          detail="Evidence chain, report hash and ledger transaction become immutable."
          right={phase === "done" ? <Badge tone="ok">SEALED</Badge> : null}
        >
          {result ? (
            <div className="stack" style={{ gap: 8 }}>
              <div className="flex-between">
                <span className="tiny muted">Evidence ID</span>
                <Hash value={result.evidence_id} chars={14} />
              </div>
              <div className="flex-between">
                <span className="tiny muted">Content SHA-256</span>
                <Hash value={result.content_sha256} chars={14} />
              </div>
              <div className="flex-between">
                <span className="tiny muted">Outcome</span>
                <StatusBadge status={result.outcome} />
              </div>
              {result.evidence_id ? (
                <button className="btn block" onClick={() => onNavigate("forensics")}>Open evidence record</button>
              ) : null}
            </div>
          ) : (
            <div className="tiny dim">Evidence becomes admissible only after the chain is recorded on the ledger.</div>
          )}
        </PipelineStep>
      </div>

      {err ? <div className="mt"><ErrorNotice error={err} /></div> : null}

      {result ? (
        <div className="mt">
          <Notice tone={result.outcome === "VERIFIED_ASSOCIATION" ? "ok" : "warn"} title={result.outcome}>
            {result.outcome_explanation}
          </Notice>
        </div>
      ) : null}
    </Panel>
  );
}

function PipelineStep({ n, label, detail, state, right, children }: {
  n: number; label: string; detail: string; state: StepState; right?: React.ReactNode; children?: React.ReactNode;
}) {
  const border = state === "pass" ? "var(--ok-line)" : state === "fail" ? "var(--crit-line)" : state === "partial" ? "var(--warn-line)" : "var(--line)";
  return (
    <div style={{
      border: `1px solid ${border}`,
      background: "var(--panel-2)",
      borderRadius: "var(--radius)",
      padding: 13,
      display: "flex", flexDirection: "column", gap: 8,
    }}>
      <div className="flex-between">
        <div className="flex gap-sm">
          <span className="mono tiny dim">0{n}</span>
          <span style={{ fontSize: 12, fontWeight: 500 }}>{label}</span>
        </div>
        {right}
      </div>
      <div className="tiny muted" style={{ marginTop: -4 }}>{detail}</div>
      <div style={{ flex: 1 }}>{children}</div>
    </div>
  );
}

/* ------------------------------------------------------------- topology */

function TopologyStrip({ topology }: { topology: Dashboard["topology"] }) {
  return (
    <Panel title="Verified topology" actions={<Badge tone="info">{topology.length} NODES</Badge>}>
      <div className="grid g3">
        {topology.map((t) => (
          <div key={t.component} className="flex gap-sm" style={{ alignItems: "flex-start" }}>
            <Dot tone={t.status === "OPERATIONAL" || t.status === "HEALTHY" ? "ok" : "warn"} />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 11.5, fontWeight: 500 }}>{t.component}</div>
              <div className="tiny muted">{t.purpose}</div>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------- honesty */

function HonestyFooter({ statement }: { statement: string }) {
  return (
    <div className="panel" style={{ padding: "13px 15px" }}>
      <div className="flex" style={{ alignItems: "flex-start" }}>
        <Badge tone="warn">SCOPE OF PROOF</Badge>
        <div className="tiny muted" style={{ flex: 1, minWidth: 0 }}>{statement}</div>
        <CopyButton text={statement} label="Copy attribution statement" />
      </div>
    </div>
  );
}
