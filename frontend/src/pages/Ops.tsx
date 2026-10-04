import { useMemo, useState } from "react";
import {
  api, endpoints,
  type AiBriefingResponse, type AiClustersResponse, type AiHealth, type AuditResponse,
  type LabOutcome, type LabScenariosResponse, type RobustnessReport,
} from "../api";
import {
  Badge, DataTable, EmptyState, ErrorNotice, FilterChips, Hash, LoadingState,
  Metric, Modal, Notice, PageHead, Panel, Pipeline, SearchInput, StatusBadge,
  Unauthorized, VerificationStep, useAsync, useToast,
} from "../components/ui";
import { IdentBadge } from "../components/layout";

/* ================================================================ audit */

export function Audit() {
  const audit = useAsync<AuditResponse>(
    () => api.get<AuditResponse>(`${endpoints.audit}?limit=200`), [],
  );
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("all");

  const rows = audit.data?.privileged_actions ?? [];
  const categories = audit.data?.categories ?? [];
  const chain = audit.data?.chain;

  const counts = useMemo(() => {
    const m: Record<string, number> = { all: rows.length };
    for (const c of categories) m[c] = rows.filter((r) => r.action === c).length;
    return m;
  }, [rows, categories]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (filter !== "all" && r.action !== filter) return false;
      if (!needle) return true;
      return [r.audit_id, r.actor_id, r.actor_role, r.action, r.target_id ?? "", r.detail, r.outcome]
        .some((v) => v?.toLowerCase().includes(needle));
    });
  }, [rows, q, filter]);

  if (audit.loading && !audit.data) return <LoadingState label="Loading audit trail" detail="GET /audit" />;
  if (audit.error) {
    const st = (audit.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={audit.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={audit.error} onRetry={audit.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Audit Trail"
        sub="Hash-chained record of privileged actions. Each entry commits to the previous one, so deleting or editing history is detectable."
        actions={
          <>
            <Badge tone="info">{rows.length} ENTRIES</Badge>
            <button className="btn" onClick={audit.reload} disabled={audit.loading}>
              {audit.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      {chain ? (
        <div className="grid g4">
          <Metric label="Chain length" value={chain.chain_length} tone="info" sub="records in the chain" />
          <Metric
            label="Chain status" small
            value={<StatusBadge status={chain.status} lg />}
            sub={chain.first_broken_record ? `breaks at ${chain.first_broken_record}` : "no break detected"}
            tone={chain.first_broken_record ? "crit" : "ok"}
          />
          <Metric label="Head hash" small value={<Hash value={chain.head} chars={14} />} sub="latest record hash" />
          <Metric label="Categories" value={categories.length} tone="info" sub="privileged action types" />
        </div>
      ) : null}

      {chain?.first_broken_record ? (
        <Notice tone="crit" title="Audit chain break detected">
          The backend reported the first inconsistent record as <span className="mono">{chain.first_broken_record}</span>.
          Entries at and after that point cannot be trusted until the cause is established.
        </Notice>
      ) : null}

      {audit.data?.note ? <Notice tone="info">{audit.data.note}</Notice> : null}

      <Panel flush>
        <div className="panel-body" style={{ borderBottom: "1px solid var(--hair)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <SearchInput value={q} onChange={setQ} placeholder="Search actor, role, action, target, detail…" width={360} />
          <FilterChips
            value={filter}
            onChange={setFilter}
            options={["all", ...categories]
              .filter((c) => c === "all" || counts[c])
              .slice(0, 9)
              .map((c) => ({ value: c, label: c === "all" ? "All" : c.replace(/[._]/g, " ").toLowerCase(), count: counts[c] ?? 0 }))}
          />
          <span className="tiny dim" style={{ marginLeft: "auto" }}>{filtered.length} of {rows.length} shown</span>
        </div>

        <DataTable
          rows={filtered}
          maxHeight={640}
          empty={<EmptyState icon="☰" title="No audit entries match" sub="Nothing in the trail matches these filters." />}
          columns={[
            { key: "t", head: "When (UTC)", render: (r) => <span className="tiny dim">{r.occurred_at?.slice(0, 19).replace("T", " ")}</span> },
            { key: "a", head: "Actor", render: (r) => (
              <span className="stack" style={{ gap: 1 }}>
                <span className="mono">{r.actor_id}</span>
                <span className="tiny dim">{r.actor_role}</span>
              </span>
            ) },
            { key: "ac", head: "Action", render: (r) => <Badge tone="info">{r.action}</Badge> },
            { key: "s", head: "Target", render: (r) => (
              <span className="stack" style={{ gap: 1 }}>
                <IdentBadge id={r.target_id} kind={r.target_type?.toLowerCase()} />
                <span className="tiny dim">{r.target_type}</span>
              </span>
            ) },
            { key: "o", head: "Outcome", render: (r) => <StatusBadge status={r.outcome} /> },
            { key: "d", head: "Detail", render: (r) => <span className="tiny muted" style={{ maxWidth: 320, display: "block" }}>{r.detail}</span> },
            { key: "h", head: "Record hash", render: (r) => <Hash value={r.record_hash} chars={10} /> },
          ]}
        />
      </Panel>
    </div>
  );
}

/* ========================================================= intelligence */

export function Intelligence() {
  const toast = useToast();
  const health = useAsync<AiHealth>(() => api.get<AiHealth>(endpoints.aiHealth), []);
  const [brief, setBrief] = useState<AiBriefingResponse | null>(null);
  const [clusters, setClusters] = useState<AiClustersResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const generate = async () => {
    setBusy(true);
    setError(null);
    try {
      setBrief(await api.post<AiBriefingResponse>(endpoints.aiBriefing, { limit: 12 }));
      toast.success("Briefing generated");
    } catch (e) {
      setError(e);
      toast.failure("Briefing refused", String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  const loadClusters = async () => {
    try {
      setClusters(await api.get<AiClustersResponse>(`${endpoints.aiClusters}?limit=20`));
    } catch (e) {
      toast.failure("Cluster view unavailable", String((e as Error).message));
    }
  };

  const live = health.data?.available ?? false;

  return (
    <div className="stack">
      <PageHead
        title="AI Intelligence"
        sub="Narration over already-verified state. The model never authorises anything, signs anything, or decides attribution."
        actions={
          <>
            <Badge tone={live ? "ok" : "idle"} lg>{health.data?.status ?? "CHECKING"}</Badge>
            <button className="btn" onClick={loadClusters}>⊞ Cluster view</button>
            <button className="btn primary" onClick={generate} disabled={busy}>
              {busy ? "Generating…" : "✦ Generate briefing"}
            </button>
          </>
        }
      />

      {health.data ? (
        <Notice tone={live ? "ok" : "warn"} title={live ? "Local model reachable" : "AI service offline"}>
          {live ? health.data.role : health.data.impact}
          {!live && health.data.reason ? ` (${health.data.reason})` : ""}
        </Notice>
      ) : null}

      <div className="grid g4">
        <Metric label="Service" value={health.data?.status ?? "—"} tone={live ? "ok" : "idle"} />
        <Metric label="Configured model" small value={health.data?.configured_model ?? "unavailable"} tone="info" />
        <Metric label="Model present" value={health.data?.model_present ? "YES" : "NO"} tone={health.data?.model_present ? "ok" : "idle"} />
        <Metric label="Endpoint" small value={health.data?.endpoint ?? "—"} tone="info" />
      </div>

      {error ? <ErrorNotice error={error} /> : null}
      {!brief && !busy && !error ? (
        <EmptyState
          icon="✦"
          title="No briefing generated yet"
          sub="Generate a briefing to have the backend summarise the deterministic state it has already verified."
          action={<button className="btn primary" onClick={generate}>Generate briefing</button>}
        />
      ) : null}
      {busy ? <LoadingState label="Summarising verified state" detail="POST /ai/briefing" /> : null}

      {brief ? (
        <div className="stack">
          <div className="grid g3">
            <Metric label="System status" small value={brief.deterministic_state.system_security_status} tone="info" />
            <Metric label="Posture" value={brief.deterministic_state.posture} tone="ok" sub="computed by the backend" />
            <Metric label="Ledger integrity" small value={brief.deterministic_state.ledger_integrity} tone="ok" />
          </div>

          <Panel
            title="Commander briefing"
            actions={<Badge tone={brief.briefing.available ? "info" : "warn"}>{brief.briefing.label}</Badge>}
          >
            {brief.briefing.available && brief.briefing.summary ? (
              <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.7 }}>{brief.briefing.summary}</p>
            ) : (
              <>
                <Notice tone="warn" title="No model narrative available">
                  The backend returned its deterministic fallback instead of a model summary. This is the honest
                  output when no model is reachable.
                </Notice>
                <p className="tiny" style={{ marginTop: 10, lineHeight: 1.7 }}>{brief.briefing.fallback}</p>
              </>
            )}
            <div className="tiny dim" style={{ marginTop: 8 }}>
              Requested {brief.briefing.requested} · generated {brief.briefing.at}
            </div>
          </Panel>
        </div>
      ) : null}

      {clusters ? (
        <Panel title="Anomaly clusters" actions={<Badge tone={clusters.available ? "ok" : "idle"}>{clusters.label}</Badge>} flush>
          <DataTable
            rows={clusters.clusters}
            empty={<EmptyState title="No clusters" sub="The backend found no recurring pattern worth grouping." />}
            columns={[
              { key: "c", head: "Category", render: (c) => <Badge tone="info">{c.category}</Badge> },
              { key: "n", head: "Events", num: true, render: (c) => c.count },
              { key: "e", head: "Most recent", render: (c) => (
                c.events?.length
                  ? <span className="tiny">{c.events[0].title}</span>
                  : <span className="dim tiny">—</span>
              ) },
            ]}
          />
          <div className="panel-body" style={{ borderTop: "1px solid var(--hair)" }}>
            <div className="tiny dim">{clusters.note}</div>
          </div>
        </Panel>
      ) : null}
    </div>
  );
}

/* ========================================================== security lab */

export function SecurityLab() {
  const toast = useToast();
  const scenarios = useAsync<LabScenariosResponse>(
    () => api.get<LabScenariosResponse>(endpoints.labScenarios), [],
  );
  const [outcomes, setOutcomes] = useState<Record<string, LabOutcome>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [detail, setDetail] = useState<LabOutcome | null>(null);

  const run = async (key: string) => {
    setBusy(key);
    try {
      const outcome = await api.post<LabOutcome>(endpoints.labSimulate, { scenario: key });
      setOutcomes((prev) => ({ ...prev, [key]: outcome }));
      if (outcome.detected) toast.success("Attack detected", outcome.detected_as);
      else toast.failure("Attack NOT detected", outcome.detected_as);
      setDetail(outcome);
    } catch (e) {
      toast.failure("Simulation refused", String((e as Error).message));
    } finally {
      setBusy(null);
    }
  };

  const runAll = async () => {
    // Sequential on purpose: each scenario mutates ledger and event state, so
    // running them concurrently would make the results incomparable.
    for (const s of scenarios.data?.scenarios ?? []) {
      await run(s.key);
    }
  };

  const ran = Object.keys(outcomes).length;
  const detected = Object.values(outcomes).filter((o) => o.detected).length;

  if (scenarios.loading && !scenarios.data) return <LoadingState label="Loading attack scenarios" detail="GET /security-lab/scenarios" />;
  if (scenarios.error) {
    const st = (scenarios.error as { status?: number }).status;
    return st === 403
      ? <Unauthorized error={scenarios.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={scenarios.error} onRetry={scenarios.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Security Lab"
        sub="Adversarial simulations against the live prototype. Each scenario states what the defence should do, then reports what the system actually did."
        actions={
          <>
            <Badge tone={ran > 0 && detected === ran ? "ok" : "warn"}>{detected}/{ran} DETECTED</Badge>
            <button className="btn primary" onClick={runAll} disabled={busy !== null}>
              {busy ? "Running…" : "▶ Run all scenarios"}
            </button>
          </>
        }
      />

      {scenarios.data?.environment ? (
        <div className="flex gap-sm">
          <Badge tone="info">ENVIRONMENT {scenarios.data.environment}</Badge>
        </div>
      ) : null}

      <Panel title="Scenario matrix" actions={<span className="tiny dim">expected defence → actual system response</span>} flush>
        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: "24%" }}>Scenario</th>
                <th style={{ width: "24%" }}>What it does</th>
                <th style={{ width: "24%" }}>Expected detection</th>
                <th style={{ width: "16%" }}>Actual response</th>
                <th style={{ width: "12%" }}>Run</th>
              </tr>
            </thead>
            <tbody>
              {(scenarios.data?.scenarios ?? []).map((s) => {
                const o = outcomes[s.key];
                return (
                  <tr key={s.key}>
                    <td>
                      <div style={{ fontSize: 11.5 }}>{s.title}</div>
                      <div className="tiny dim mono">{s.key}</div>
                    </td>
                    <td className="tiny muted">{s.what_it_does}</td>
                    <td className="tiny muted">{s.expected_detection}</td>
                    <td>
                      {o ? (
                        <span className="stack" style={{ gap: 3 }}>
                          <StatusBadge status={o.outcome} />
                          <span className="tiny dim">{o.detected_as}</span>
                        </span>
                      ) : <span className="dim tiny">not run</span>}
                    </td>
                    <td>
                      <span className="flex gap-sm">
                        <button className="btn sm" disabled={busy !== null} onClick={() => run(s.key)}>
                          {busy === s.key ? "…" : "Run"}
                        </button>
                        {o ? (
                          <Badge tone={o.detected ? "ok" : "crit"}>{o.detected ? "DETECTED" : "MISSED"}</Badge>
                        ) : null}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>

      {ran > 0 ? (
        <Panel
          title="Detection summary"
          actions={<Badge tone={detected === ran ? "ok" : "crit"}>{detected}/{ran}</Badge>}
        >
          <Pipeline>
            {Object.entries(outcomes).map(([key, o]) => (
              <VerificationStep
                key={key} state={o.detected ? "pass" : "fail"}
                name={key.replace(/_/g, " ")}
                detail={o.detail}
                right={<StatusBadge status={o.detected ? "DETECTED" : "MISSED"} />}
              />
            ))}
          </Pipeline>
        </Panel>
      ) : null}

      {scenarios.data?.disclaimer ? <Notice tone="warn">{scenarios.data.disclaimer}</Notice> : null}

      {detail ? (
        <Modal
          title="Simulation outcome" sub={detail.label} onClose={() => setDetail(null)}
          footer={<button className="btn" onClick={() => setDetail(null)}>Close</button>}
        >
          <div className={`evidence ${detail.detected ? "" : "bad"}`}>
            <h2>{detail.detected ? "ATTACK DETECTED" : "ATTACK NOT DETECTED"}</h2>
            <div className="sub">Classified as {detail.detected_as}</div>
          </div>
          <div className="mt">
            <dl className="kv">
              <dt>Simulation</dt><dd>{detail.simulation}</dd>
              <dt>Outcome</dt><dd><StatusBadge status={detail.outcome} /></dd>
              <dt>Executed at</dt><dd>{detail.executed_at}</dd>
            </dl>
            <div className="hr" />
            <p className="tiny" style={{ margin: 0, lineHeight: 1.65 }}>{detail.detail}</p>
          </div>
        </Modal>
      ) : null}
    </div>
  );
}

/* ====================================================== watermark probe */

export function WatermarkProbe() {
  const probe = useAsync<RobustnessReport>(
    () => api.get<RobustnessReport>(endpoints.robustness), [],
  );
  const rows = probe.data?.results ?? [];

  if (probe.loading && !probe.data) return <LoadingState label="Measuring watermark robustness" detail="GET /watermarks/robustness" />;
  if (probe.error) {
    const st = (probe.error as { status?: number }).status;
    return st === 403
      ? <Unauthorized error={probe.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={probe.error} onRetry={probe.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Watermark Probe"
        sub="How far the embedded watermark survives real transformations. These are measurements taken from the running engine, not target values."
        actions={
          <>
            <Badge tone={probe.data?.transformations_recovered === probe.data?.transformations_tested ? "ok" : "warn"} lg>
              {probe.data?.transformations_recovered ?? 0}/{probe.data?.transformations_tested ?? 0} RECOVERED
            </Badge>
            <button className="btn" onClick={probe.reload} disabled={probe.loading}>
              {probe.loading ? "Measuring…" : "↻ Re-measure"}
            </button>
          </>
        }
      />

      <div className="grid g4">
        <Metric label="Transformations" value={probe.data?.transformations_tested ?? 0} tone="info" />
        <Metric
          label="Recovered" value={probe.data?.transformations_recovered ?? 0}
          tone={probe.data?.transformations_recovered === probe.data?.transformations_tested ? "ok" : "warn"}
        />
        <Metric
          label="Recovery rate"
          value={probe.data?.transformations_tested
            ? `${Math.round((probe.data.transformations_recovered / probe.data.transformations_tested) * 100)}%`
            : "—"}
          tone="ok"
        />
        <Metric label="Measured at" small value={probe.data?.tested_at ?? "—"} tone="info" />
      </div>

      <Panel title="Transformation results" flush>
        <DataTable
          rows={rows}
          empty={<EmptyState icon="◐" title="No measurements" sub="The backend returned no robustness rows." />}
          columns={[
            { key: "t", head: "Transformation", render: (r) => r.transformation.replace(/_/g, " ") },
            { key: "c", head: "Carrier-to-noise", num: true, render: (r) => r.carrier_to_noise_ratio.toFixed(2) },
            { key: "b", head: "Bit errors", num: true, render: (r) => r.estimated_bit_errors },
            {
              key: "r", head: "Tag recovered", render: (r) => (
                <Badge tone={r.recovered ? "ok" : "crit"}>{r.recovered ? "RECOVERED" : "LOST"}</Badge>
              ),
            },
            { key: "v", head: "Verdict", render: (r) => (
              <StatusBadge status={r.recovered ? "VERIFIED" : "UNVERIFIED"} />
            ) },
          ]}
        />
      </Panel>

      <Panel title="What a lost row means" tone="warn">
        <Notice tone="warn" title="A lost tag is a real limitation, reported as one">
          When a transformation destroys the carriers, the extractor returns no tag and the console shows LOST. It
          never falls back to guessing from file metadata, timestamps or visual similarity.
        </Notice>
        {probe.data?.known_limitations?.length ? (
          <ul className="stack" style={{ gap: 5, paddingLeft: 18, marginTop: 10, marginBottom: 0 }}>
            {probe.data.known_limitations.map((l) => <li key={l} className="tiny muted">{l}</li>)}
          </ul>
        ) : null}
      </Panel>
    </div>
  );
}
