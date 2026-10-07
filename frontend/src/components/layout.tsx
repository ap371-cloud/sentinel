import { useEffect, useState, type ReactNode } from "react";
import { Badge, CopyButton, Dot, StatusBadge } from "./ui";

/* ------------------------------------------------------------------- nav */

export type NavEntry = {
  id: string;
  label: string;
  ico: string;
  /** Any one of these permissions makes the view reachable. */
  needs: string[];
};

/** One entry per console view. Where a file already renders several related
 * screens they are tabs inside that view rather than separate nav rows. */
export const NAV: NavEntry[] = [
  { id: "command", label: "Command Centre", ico: "◈", needs: ["commander.dashboard"] },
  { id: "documents", label: "Documents", ico: "▤", needs: ["document.read"] },
  { id: "sessions", label: "Decryption Sessions", ico: "⊛", needs: ["document.decrypt"] },
  { id: "identity", label: "Recipients & Devices", ico: "◍", needs: ["recipient.create", "device.manage"] },
  { id: "approvals", label: "Approvals", ico: "⚿", needs: ["approval.request", "approval.decide"] },
  { id: "forensics", label: "Forensics", ico: "⌕", needs: ["evidence.read"] },
  { id: "security", label: "Security", ico: "⚡", needs: ["incident.manage"] },
  { id: "ledger", label: "Ledger", ico: "⛓", needs: ["ledger.read"] },
  { id: "oversight", label: "Oversight", ico: "☰", needs: ["audit.read"] },
];

export function navVisible(entry: NavEntry, permissions: string[]): boolean {
  return entry.needs.some((p) => permissions.includes(p));
}

/* ------------------------------------------------------------------ props */

export type Operator = {
  id: string;
  display_name: string;
  role: string;
  unit?: string;
  clearance?: number;
  permissions: string[];
};

export type ShellStatus = {
  postureScore: number | null;
  postureRating: string;
  quorum: string;
  openIncidents: number;
  criticalIncidents: number;
  pendingApprovals: number;
  systemStatus: string;
  aiStatus: string;
};

export type ShellProps = {
  page: string;
  operator: Operator | null;
  status: ShellStatus;
  lockdown: LockdownInfo | null;
  onNavigate: (id: string) => void;
  onLogout: () => void;
  children: ReactNode;
};

export type LockdownInfo = { active: boolean; reason: string | null; activated_at: string | null };

/* ------------------------------------------------------------------ shell */

export function Shell({ page, operator, status, lockdown, onNavigate, onLogout, children }: ShellProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    const stored = localStorage.getItem("sentinel-theme");
    if (stored === "light" || stored === "dark") return stored;
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("sentinel-theme", theme);
  }, [theme]);

  const current = NAV.find((n) => n.id === page) ?? NAV[0];
  const initials = (operator?.display_name ?? operator?.id ?? "??")
    .split(/[\s-]+/).filter(Boolean).slice(0, 2).map((p) => p[0]?.toUpperCase() ?? "").join("");

  const allowed = NAV.filter((n) => navVisible(n, operator?.permissions ?? []));
  const alertCount = status.openIncidents;

  return (
    <div className={`shell ${collapsed ? "collapsed" : ""}`}>
      <nav className="sidebar" aria-label="Primary">
        <div className="brand">
          <span className="brand-mark" aria-hidden>◈</span>
          <span className="brand-text">
            <b>SENTINEL</b>
            <span>Document Security</span>
          </span>
        </div>

        <div className="nav">
          {allowed.map((n) => {
            const badge = navCount(n.id, status);
            return (
              <div
                key={n.id}
                className={`nav-item ${page === n.id ? "active" : ""}`}
                onClick={() => onNavigate(n.id)}
                role="link"
                tabIndex={0}
                aria-current={page === n.id ? "page" : undefined}
                title={collapsed ? n.label : undefined}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onNavigate(n.id); } }}
              >
                <span className="ico" aria-hidden>{n.ico}</span>
                <span className="lbl">{n.label}</span>
                {badge ? <span className={`count ${badge.alert ? "alert" : ""}`}>{badge.n}</span> : null}
              </div>
            );
          })}
        </div>

        <div className="side-foot">
          <div className="foot-body">
            <div className="foot-line">
              <span>POSTURE</span>
              <b style={{ color: postureColor(status.postureScore) }}>
                {status.postureScore ?? "—"}{status.postureRating ? ` ${status.postureRating}` : ""}
              </b>
            </div>
            <div className="foot-line">
              <span>QUORUM</span>
              <b>{status.quorum}</b>
            </div>
            <div className="foot-line">
              <span>LINK</span>
              <b style={{ color: "var(--ok)" }}>LOOPBACK</b>
            </div>
          </div>
          <div className="side-user">
            <span className="avatar" aria-hidden>{initials || "??"}</span>
            <span className="who">
              <b>{operator?.display_name ?? operator?.id ?? "—"}</b>
              <span>{operator?.role ?? "UNAUTHENTICATED"}</span>
            </span>
          </div>
        </div>
      </nav>

      <div className="main">
        {lockdown?.active ? (
          <div className="lockdown-banner" role="alert">
            <Dot tone="crit" pulse />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="t">EMERGENCY LOCKDOWN ACTIVE</div>
              <div className="d">
                All decryption authorisation is refused. Reason: {lockdown.reason ?? "not recorded"}
                {lockdown.activated_at ? ` · since ${lockdown.activated_at.replace("T", " ").slice(0, 19)}` : ""}
              </div>
            </div>
          </div>
        ) : null}

        <header className="topbar">
          <button
            className="icon-btn"
            onClick={() => setCollapsed((c) => !c)}
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            title={collapsed ? "Expand navigation" : "Collapse navigation"}
          >
            {collapsed ? "»" : "«"}
          </button>

          <div className="topbar-title">
            <b>{current.label.toUpperCase()}</b>
          </div>

          <div className="topbar-spacer" />

          <span className={`env-chip ${status.systemStatus === "DEGRADED" ? "warn" : ""}`}>
            <Dot tone={status.systemStatus === "DEGRADED" ? "warn" : "ok"} pulse />
            {status.systemStatus}
          </span>

          <button
            className="icon-btn"
            onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            {theme === "dark" ? "☾" : "☀"}
          </button>

          <button
            className="icon-btn"
            onClick={() => onNavigate("security")}
            aria-label={`${alertCount} open incidents`}
            title="Open incidents"
          >
            ⚑
            {alertCount > 0 ? <span className="pip">{alertCount > 99 ? "99+" : alertCount}</span> : null}
          </button>

          <button className="icon-btn" onClick={onLogout} aria-label="Sign out" title="Sign out">
            ⏻
          </button>
        </header>

        <main className="content">{children}</main>
      </div>
    </div>
  );
}

function navCount(id: string, s: ShellStatus): { n: number; alert: boolean } | null {
  if (id === "security" && s.openIncidents) return { n: s.openIncidents, alert: s.criticalIncidents > 0 };
  if (id === "approvals" && s.pendingApprovals) return { n: s.pendingApprovals, alert: false };
  return null;
}

function postureColor(score: number | null): string {
  if (score === null) return "var(--muted)";
  if (score >= 90) return "var(--ok)";
  if (score >= 70) return "var(--warn)";
  return "var(--crit)";
}

/* ------------------------------------------------------------- utilities */

export function IdentBadge({ id, kind = "document" }: { id?: string | null; kind?: string }) {
  if (!id) return <span className="dim tiny">—</span>;
  return (
    <span className="hash">
      <span>{id}</span>
      <CopyButton text={id} label={`Copy ${kind} ID`} />
    </span>
  );
}

export function QuorumChip({ nodes, quorumSize }: { nodes: { status: string }[]; quorumSize: number }) {
  const healthy = nodes.filter((n) => n.status === "HEALTHY" || n.status === "ONLINE" || n.status === "SYNCED").length;
  return <Badge tone={healthy >= quorumSize ? "ok" : "crit"}>QUORUM {healthy}/{nodes.length}</Badge>;
}

export function SystemStatusLine({ status }: { status: { status: string } }) {
  return <StatusBadge status={status.status} />;
}