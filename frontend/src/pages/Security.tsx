import { useMemo, useState } from "react";
import {
  api, endpoints,
  type IncidentRow, type RiskDetail, type RiskLeaderboardResponse,
  type SecurityEvent, type SecurityEventsResponse,
} from "../api";
import {
  Badge, DataTable, Drawer, EmptyState, ErrorNotice, Field, FilterChips, LoadingState,
  Metric, Modal, Notice, PageHead, Panel, SearchInput, SeverityBadge, StatusBadge,
  Timeline, Unauthorized, useAsync, useToast,
} from "../components/ui";
import { IdentBadge } from "../components/layout";

const SEVERITIES = ["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
type Sev = typeof SEVERITIES[number];

/* ======================================================= security events */

export function SecurityEvents() {
  const toast = useToast();
  const events = useAsync<SecurityEventsResponse>(
    () => api.get<SecurityEventsResponse>(`${endpoints.securityEvents}?limit=100`), [],
  );
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<Sev>("all");
  const [open, setOpen] = useState<SecurityEvent | null>(null);
  const [raiseFor, setRaiseFor] = useState<SecurityEvent | null>(null);

  const rows = events.data?.events ?? [];
  const counts = events.data?.counts_by_severity ?? {};
  const chipCounts = {
    all: rows.length,
    CRITICAL: counts.CRITICAL ?? 0,
    HIGH: counts.HIGH ?? 0,
    MEDIUM: counts.MEDIUM ?? 0,
    LOW: counts.LOW ?? 0,
  };

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (sev !== "all" && r.severity !== sev) return false;
      if (!needle) return true;
      return [r.security_event_id, r.title, r.category, r.plain_explanation]
        .some((v) => v?.toLowerCase().includes(needle));
    });
  }, [rows, q, sev]);

  const acknowledge = async (e: SecurityEvent) => {
    try {
      await api.post(endpoints.acknowledgeEvent(e.security_event_id), { note: "Reviewed in the event console" });
      toast.success("Event acknowledged", e.security_event_id);
      events.reload();
    } catch (err) {
      toast.failure("Acknowledgement refused", String((err as Error).message));
    }
  };

  if (events.loading && !events.data) return <LoadingState label="Loading security events" detail="GET /security-events" />;
  if (events.error) {
    const st = (events.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={events.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={events.error} onRetry={events.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Security Events"
        sub="Detection output from the policy engine. Every event carries a plain-language brief: what happened, why it matters, what was affected, and what to do."
        actions={
          <>
            <Badge tone={counts.CRITICAL ? "crit" : "ok"}>{rows.length} EVENTS</Badge>
            <button className="btn" onClick={events.reload} disabled={events.loading}>
              {events.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      <div className="grid g4">
        <Metric label="Critical" value={chipCounts.CRITICAL} tone={chipCounts.CRITICAL ? "crit" : "ok"} />
        <Metric label="High" value={chipCounts.HIGH} tone={chipCounts.HIGH ? "high" : "ok"} />
        <Metric label="Medium" value={chipCounts.MEDIUM} tone={chipCounts.MEDIUM ? "warn" : "ok"} />
        <Metric label="Low" value={chipCounts.LOW} tone="info" />
      </div>

      <Panel flush>
        <div className="panel-body" style={{ borderBottom: "1px solid var(--hair)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <SearchInput value={q} onChange={setQ} placeholder="Search event, category, title, explanation…" width={340} />
          <FilterChips
            value={sev}
            onChange={setSev}
            options={SEVERITIES.map((s) => ({
              value: s,
              label: s === "all" ? "All" : s,
              count: chipCounts[s as keyof typeof chipCounts],
            }))}
          />
          <span className="tiny dim" style={{ marginLeft: "auto" }}>
            {filtered.length} of {rows.length} shown
            {events.data?.open_count ? ` · ${events.data.open_count} open` : ""}
          </span>
        </div>

        <DataTable
          rows={filtered}
          onRow={(r) => setOpen(r)}
          empty={<EmptyState icon="⚡" title="No events match" sub={q || sev !== "all" ? "Relax the filters to see the full queue." : "The policy engine has not raised anything."} />}
          columns={[
            { key: "s", head: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
            { key: "t", head: "Event", render: (r) => (
              <span className="stack" style={{ gap: 2 }}>
                <span>{r.title}</span>
                <span className="tiny dim">{r.category}</span>
              </span>
            ) },
            { key: "i", head: "Event ID", render: (r) => <IdentBadge id={r.security_event_id} kind="event" /> },
            { key: "d", head: "Detected (UTC)", render: (r) => <span className="tiny dim">{r.detected_at?.slice(0, 19).replace("T", " ")}</span> },
            { key: "st", head: "Status", render: (r) => <StatusBadge status={r.status} /> },
            {
              key: "a", head: "", render: (r) => (
                r.status === "OPEN" || r.status === "NEW"
                  ? <button className="btn sm" onClick={() => acknowledge(r)}>Acknowledge</button>
                  : null
              ),
            },
          ]}
        />
      </Panel>

      {open ? <EventDrawer event={open} onClose={() => setOpen(null)} onRaise={() => { setRaiseFor(open); setOpen(null); }} /> : null}
      {raiseFor ? (
        <RaiseIncident
          event={raiseFor}
          onClose={() => setRaiseFor(null)}
          onDone={() => toast.success("Incident raised", `${raiseFor.security_event_id} promoted to an owned record.`)}
        />
      ) : null}
    </div>
  );
}

function EventDrawer({ event, onClose, onRaise }: {
  event: SecurityEvent; onClose: () => void; onRaise: () => void;
}) {
  const b = event.command_brief;
  const openish = event.status === "OPEN" || event.status === "NEW";

  return (
    <Drawer
      title={event.title}
      sub={<IdentBadge id={event.security_event_id} kind="event" />}
      onClose={onClose}
      actions={openish ? <button className="btn sm danger" onClick={onRaise}>✖ Raise incident</button> : null}
    >
      <div className="stack">
        <div className="flex wrap gap-sm">
          <SeverityBadge severity={event.severity} />
          <StatusBadge status={event.status} lg />
          <Badge tone="info" lg>{event.category}</Badge>
        </div>

        <Panel title="What happened">
          <p className="tiny" style={{ margin: 0, lineHeight: 1.65 }}>{b.what_happened}</p>
        </Panel>
        <Panel title="Why it is important">
          <p className="tiny" style={{ margin: 0, lineHeight: 1.65 }}>{b.why_it_is_important}</p>
        </Panel>
        <Panel title="What was affected">
          <p className="tiny" style={{ margin: 0, lineHeight: 1.65 }}>{b.what_was_affected}</p>
        </Panel>
        <Panel title="Recommended action" tone="warn">
          <ol className="stack" style={{ gap: 5, paddingLeft: 18, margin: 0 }}>
            {b.recommended_action.split("\n").filter(Boolean).map((line, i) => (
              <li key={i} className="tiny">{line.replace(/^\s*[-*\d.]+\s*/, "")}</li>
            ))}
          </ol>
        </Panel>

        <Panel title="Detection detail">
          <p className="tiny muted" style={{ margin: 0, lineHeight: 1.65 }}>{event.plain_explanation}</p>
          <div className="hr" />
          <dl className="kv">
            <dt>Detected at</dt><dd>{event.detected_at}</dd>
            <dt>Category</dt><dd>{event.category}</dd>
          </dl>
        </Panel>
      </div>
    </Drawer>
  );
}

/* ============================================================= incidents */

export function Incidents() {
  const toast = useToast();
  const incidents = useAsync<{ incidents: IncidentRow[] }>(() => api.get(endpoints.incidents), []);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"all" | "OPEN" | "CLOSED">("all");
  const [openId, setOpenId] = useState<string | null>(null);
  const [raiseFor, setRaiseFor] = useState<SecurityEvent | null>(null);

  const rows = incidents.data?.incidents ?? [];
  const counts = useMemo(() => ({
    all: rows.length,
    OPEN: rows.filter((r) => r.status !== "CLOSED" && r.status !== "RESOLVED").length,
    CLOSED: rows.filter((r) => r.status === "CLOSED" || r.status === "RESOLVED").length,
  }), [rows]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      const open = r.status !== "CLOSED" && r.status !== "RESOLVED";
      if (filter === "OPEN" && !open) return false;
      if (filter === "CLOSED" && open) return false;
      if (!needle) return true;
      return [r.incident_id, r.title, r.owner_id ?? "", r.severity, r.category, r.what_happened]
        .some((v) => v?.toLowerCase().includes(needle));
    });
  }, [rows, q, filter]);

  if (incidents.loading && !incidents.data) return <LoadingState label="Loading incidents" detail="GET /incidents" />;
  if (incidents.error) {
    const st = (incidents.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={incidents.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={incidents.error} onRetry={incidents.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Incidents"
        sub="A detection promoted into something a named officer owns. Each incident keeps its originating event and any linked case."
        actions={
          <>
            <Badge tone={counts.OPEN ? "warn" : "ok"}>{counts.OPEN} OPEN</Badge>
            <button className="btn" onClick={incidents.reload} disabled={incidents.loading}>
              {incidents.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      <div className="grid g4">
        <Metric label="Open" value={counts.OPEN} tone={counts.OPEN ? "warn" : "ok"} />
        <Metric label="Critical" value={rows.filter((r) => r.severity === "CRITICAL").length} tone="crit" />
        <Metric label="High" value={rows.filter((r) => r.severity === "HIGH").length} tone="high" />
        <Metric label="Total" value={rows.length} tone="info" />
      </div>

      <Panel flush>
        <div className="panel-body" style={{ borderBottom: "1px solid var(--hair)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <SearchInput value={q} onChange={setQ} placeholder="Search incident, title, owner, category…" width={340} />
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
          onRow={(r) => setOpenId(r.incident_id)}
          empty={
            <EmptyState
              icon="✖"
              title="No incidents"
              sub="Promote a security event into an incident from the event console when a detection needs an owner."
            />
          }
          columns={[
            { key: "s", head: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
            { key: "t", head: "Incident", render: (r) => (
              <span className="stack" style={{ gap: 2 }}>
                <span>{r.title}</span>
                <span className="tiny dim">{r.category}</span>
              </span>
            ) },
            { key: "i", head: "Incident ID", render: (r) => <IdentBadge id={r.incident_id} kind="incident" /> },
            { key: "o", head: "Owner", render: (r) => <span className="mono">{r.owner_id ?? "unassigned"}</span> },
            { key: "op", head: "Opened (UTC)", render: (r) => <span className="tiny dim">{r.opened_at?.slice(0, 19).replace("T", " ")}</span> },
            { key: "st", head: "Status", render: (r) => <StatusBadge status={r.status} /> },
          ]}
        />
      </Panel>

      {openId ? <IncidentDrawer id={openId} onClose={() => setOpenId(null)} /> : null}
      {raiseFor ? (
        <RaiseIncident
          event={raiseFor}
          onClose={() => setRaiseFor(null)}
          onDone={() => { incidents.reload(); toast.success("Incident raised", `${raiseFor.security_event_id} promoted to an owned record.`); }}
        />
      ) : null}
    </div>
  );
}

function IncidentDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const incidents = useAsync<{ incidents: IncidentRow[] }>(() => api.get(endpoints.incidents), []);
  const inc = incidents.data?.incidents.find((i) => i.incident_id === id);

  return (
    <Drawer title={inc?.title ?? "Incident"} sub={<IdentBadge id={id} kind="incident" />} onClose={onClose}>
      {incidents.loading && !inc ? <LoadingState label="Loading incident" /> : null}
      {!inc && !incidents.loading ? <EmptyState title="Incident not found" sub="It may have been closed and archived." /> : null}

      {inc ? (
        <div className="stack">
          <div className="flex wrap gap-sm">
            <SeverityBadge severity={inc.severity} />
            <StatusBadge status={inc.status} lg />
            <Badge tone="info" lg>{inc.category}</Badge>
          </div>

          <Panel title="Incident record">
            <dl className="kv">
              <dt>Incident ID</dt><dd>{inc.incident_id}</dd>
              <dt>Owner</dt><dd>{inc.owner_id ?? "unassigned"}</dd>
              <dt>Opened</dt><dd>{inc.opened_at}</dd>
              <dt>Closed</dt><dd>{inc.closed_at ?? "—"}</dd>
              <dt>Linked event</dt><dd><IdentBadge id={inc.linked_event_id} kind="event" /></dd>
              <dt>Linked case</dt><dd><IdentBadge id={inc.linked_case_id} kind="case" /></dd>
            </dl>
          </Panel>

          <Panel title="What happened">
            <p className="tiny" style={{ margin: 0, lineHeight: 1.65 }}>{inc.what_happened}</p>
          </Panel>
          <Panel title="Why it matters">
            <p className="tiny" style={{ margin: 0, lineHeight: 1.65 }}>{inc.why_it_matters}</p>
          </Panel>
          <Panel title="Affected resources">
            {inc.affected_resources.length ? (
              <div className="pill-row">
                {inc.affected_resources.map((r) => <IdentBadge key={r} id={r} kind="resource" />)}
              </div>
            ) : <span className="dim tiny">None recorded.</span>}
          </Panel>
          <Panel title="Recommended response" tone="warn">
            <ol className="stack" style={{ gap: 5, paddingLeft: 18, margin: 0 }}>
              {inc.recommended_response.map((line, i) => <li key={i} className="tiny">{line}</li>)}
            </ol>
          </Panel>

          <Panel title="Timeline" flush>
            <Timeline
              items={(inc.timeline ?? []).map((entry, i) => ({
                id: `${entry.at}-${i}`,
                time: entry.at,
                title: entry.text,
              }))}
            />
          </Panel>
        </div>
      ) : null}
    </Drawer>
  );
}

function RaiseIncident({ event, onClose, onDone }: {
  event: SecurityEvent; onClose: () => void; onDone: () => void;
}) {
  const [title, setTitle] = useState(event.title);
  const [responses, setResponses] = useState(event.command_brief.recommended_action.split("\n").filter(Boolean).join("\n"));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post(endpoints.incidents, {
        security_event_id: event.security_event_id,
        title,
        recommended_response: responses.split("\n").map((r) => r.trim()).filter(Boolean),
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
      title="Raise incident"
      sub={<IdentBadge id={event.security_event_id} kind="event" />}
      onClose={onClose}
      danger
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn danger" onClick={submit} disabled={busy || title.trim().length < 5}>
            {busy ? "Raising…" : "Raise incident"}
          </button>
        </>
      }
    >
      <Notice tone="warn" title="This creates an owned record">
        An incident is tracked, reported on and closed by a named officer. The source event stays linked.
      </Notice>
      <div className="mt">
        <Field label="Title">
          <input className="inp" value={title} onChange={(e) => setTitle(e.target.value)} />
        </Field>
        <Field label="Recommended response" hint="one action per line">
          <textarea className="inp" rows={5} value={responses} onChange={(e) => setResponses(e.target.value)} />
        </Field>
      </div>
      {error ? <ErrorNotice error={error} /> : null}
    </Modal>
  );
}

/* ============================================================= risk console */

export function RiskConsole() {
  const list = useAsync<RiskLeaderboardResponse>(
    () => api.get<RiskLeaderboardResponse>(`${endpoints.risk}?limit=500`), [],
  );
  const [openId, setOpenId] = useState<string | null>(null);

  const rows = list.data?.recipients ?? [];
  const maximum = list.data?.maximum ?? 100;
  const elevated = rows.filter((r) => r.risk_level === "HIGH" || r.risk_level === "CRITICAL").length;

  if (list.loading && !list.data) return <LoadingState label="Scoring identities" detail="GET /risk" />;
  if (list.error) {
    const st = (list.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={list.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={list.error} onRetry={list.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Identity Risk"
        sub="Rule-based and explainable: every point names the recorded factor behind it. The score is informational — it never makes an authorisation decision on its own."
        actions={
          <>
            <Badge tone="info">{rows.length} IDENTITIES SCORED</Badge>
            <button className="btn" onClick={list.reload} disabled={list.loading}>
              {list.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      <div className="grid g4">
        <Metric label="Identities scored" value={rows.length} tone="info" />
        <Metric label="High / critical" value={elevated} tone={elevated ? "crit" : "ok"} sub="risk level HIGH or CRITICAL" />
        <Metric
          label="Top score" value={rows.length ? rows[0].risk_score : 0}
          tone={rows[0]?.risk_level === "CRITICAL" ? "crit" : "info"}
          sub={rows[0] ? `held by ${rows[0].recipient_id}` : "no identity scored"}
        />
        <Metric label="Scale" small value={maximum} tone="idle" sub="maximum possible score" />
      </div>

      <Panel flush>
        <DataTable
          rows={rows}
          onRow={(r) => setOpenId(r.recipient_id)}
          empty={
            <EmptyState icon="◍" title="No identities scored" sub="The backend returned an empty risk leaderboard." />
          }
          columns={[
            { key: "r", head: "Recipient", render: (r) => <IdentBadge id={r.recipient_id} kind="recipient" /> },
            { key: "l", head: "Level", render: (r) => <RiskLevelBadge level={r.risk_level} /> },
            { key: "s", head: "Score", num: true, render: (r) => (
              <span className="flex gap-sm" style={{ justifyContent: "flex-end" }}>
                <b style={{ color: riskColor(r.risk_level) }}>{r.risk_score}</b>
                <span className="tiny dim">/ {maximum}</span>
              </span>
            ) },
            { key: "f", head: "Factors", num: true, render: (r) => r.factor_count },
            { key: "d", head: "", render: () => <span className="tiny dim">drill down</span> },
          ]}
        />
      </Panel>

      {openId ? <RiskDrawer id={openId} onClose={() => setOpenId(null)} /> : null}
    </div>
  );
}

function RiskLevelBadge({ level }: { level: string }) {
  const tone = level === "CRITICAL" ? "crit" : level === "HIGH" ? "high" : level === "MEDIUM" ? "warn" : level === "LOW" ? "info" : "ok";
  return <Badge tone={tone}>{level}</Badge>;
}

function riskColor(level: string): string {
  if (level === "CRITICAL") return "var(--crit)";
  if (level === "HIGH") return "var(--high)";
  if (level === "MEDIUM") return "var(--warn)";
  if (level === "LOW") return "var(--info)";
  return "var(--ok)";
}

function RiskDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const detail = useAsync<RiskDetail>(() => api.get<RiskDetail>(endpoints.riskDetail(id)), [id]);
  const d = detail.data;

  return (
    <Drawer title="Risk assessment" sub={<IdentBadge id={id} kind="recipient" />} onClose={onClose}>
      {detail.loading && !d ? <LoadingState label="Computing risk drill-down" detail="GET /risk/{id}" /> : null}
      {detail.error ? <ErrorNotice error={detail.error} onRetry={detail.reload} /> : null}
      {d ? (
        <div className="stack">
          <div className="grid g3">
            <Metric label="Score" value={d.risk_score} tone={d.risk_level === "CRITICAL" ? "crit" : "info"} sub={`out of ${d.maximum}`} />
            <Metric label="Level" small value={<RiskLevelBadge level={d.risk_level} />} tone="idle" />
            <Metric label="Assessed at" small value={d.assessment_at?.slice(0, 19).replace("T", " ")} tone="idle" />
          </div>

          <Panel title="Contributing factors" flush>
            {d.contributing_factors.length ? (
              <div className="pipeline">
                {d.contributing_factors.map((f) => (
                  <div key={f.factor} className="vstep partial">
                    <span className="mark">+{f.points}</span>
                    <div>
                      <div className="nm">{f.factor.replace(/_/g, " ")}</div>
                      {f.evidence?.length ? <div className="dt">{f.evidence.join(" · ")}</div> : null}
                      {f.detail ? <div className="dt dim">{f.detail}</div> : null}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon="✓" title="No contributing factors" sub="This identity currently scores zero risk points." />
            )}
          </Panel>

          <Notice tone="info" title="How the score works">
            {d.plain_explanation}
          </Notice>
        </div>
      ) : null}
    </Drawer>
  );
}
