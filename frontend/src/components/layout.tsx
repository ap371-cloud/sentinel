import { useState, type ReactNode } from "react";
import { Badge, CopyButton, Dot, StatusBadge } from "./ui";

/* ------------------------------------------------------------------- nav */

export type NavEntry = {
  id: string;            // unique nav-key
  route: string;         // target page route
  tab?: string;          // sub-tab within the route
  label: string;
  ico: string;
  needs: string[];
};

/** One entry per console view. Where a file already renders several related
 *  screens they are tabs inside that view rather than separate nav rows. */
export const NAV: NavEntry[] = [
  { id: "overview", route: "command", label: "Overview", ico: "dashboard", needs: ["commander.dashboard"] },
  { id: "documents", route: "documents", label: "Documents", ico: "description", needs: ["document.read"] },
  { id: "sessions", route: "sessions", label: "Decryption Sessions", ico: "lock_clock", needs: ["document.decrypt"] },
  { id: "identities", route: "identity", tab: "recipients", label: "Identities", ico: "badge", needs: ["recipient.create", "device.manage"] },
  { id: "devices", route: "identity", tab: "devices", label: "Devices", ico: "devices", needs: ["device.manage"] },
  { id: "approvals", route: "approvals", label: "Approvals", ico: "verified", needs: ["approval.request", "approval.decide"] },
  { id: "intelligence", route: "forensics", tab: "verify", label: "Intelligence", ico: "psychology", needs: ["evidence.read"] },
  { id: "alerts", route: "security", tab: "events", label: "Alerts", ico: "warning", needs: ["incident.manage"] },
  { id: "investigations", route: "forensics", tab: "cases", label: "Investigations", ico: "radar", needs: ["evidence.read"] },
  { id: "audit", route: "oversight", label: "Audit", ico: "history", needs: ["audit.read"] },
  { id: "ledger", route: "ledger", label: "Ledger", ico: "account_balance", needs: ["ledger.read"] },
  { id: "policies", route: "security", tab: "policies", label: "Policies", ico: "policy", needs: ["incident.manage"] },
  { id: "settings", route: "settings", label: "Settings", ico: "settings", needs: [] },
];

export function navVisible(entry: NavEntry, permissions: string[]): boolean {
  return entry.needs.length === 0 || entry.needs.some((p) => permissions.includes(p));
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

  const current = NAV.find((n) => n.route === page) ?? NAV[0];
  const initials = (operator?.display_name ?? operator?.id ?? "??")
    .split(/[\s-]+/).filter(Boolean).slice(0, 2).map((p) => p[0]?.toUpperCase() ?? "").join("");

  const allowed = NAV.filter((n) => navVisible(n, operator?.permissions ?? []));
  const alertCount = status.openIncidents;

  return (
    <div className={`shell ${collapsed ? "collapsed" : ""}`}>
      <nav className="sidebar" aria-label="Primary">
        <div className="px-4">
          <div className="flex items-center gap-2 mb-4">
            <div className="brand-mark" aria-hidden>S</div>
            <div className="overflow-hidden">
              <span className="brand-text b">SENTINEL</span>
              <span className="brand-text span">SECURE COMMAND</span>
            </div>
          </div>

          <nav className="space-y-0.5" data-active-classes="bg-primary-container text-on-primary-container font-semibold">
            {allowed.map((n) => {
              const badge = navCount(n.route, status);
              return (
                <div
                  key={n.id}
                  className={`nav-item ${page === n.route ? "active" : ""}`}
                  onClick={() => onNavigate(n.route)}
                  role="link"
                  tabIndex={0}
                  aria-current={page === n.route ? "page" : undefined}
                  title={collapsed ? n.label : undefined}
                  onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onNavigate(n.route); } }}
                >
                  <span className="material-symbols-outlined text-[18px] ico" aria-hidden>{n.ico}</span>
                  <span className="lbl">{n.label}</span>
                  {badge ? <span className={`count ${badge.alert ? "alert" : ""}`}>{badge.n}</span> : null}
                </div>
              );
            })}
          </nav>
        </div>

        <div className="side-foot">
          <div className="foot-body">
            <div className="flex items-center justify-between text-xs">
              <span className="text-on-surface-variant">Air-gapped mode</span>
              <b className="text-primary font-mono font-bold">ACTIVE</b>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-on-surface-variant">Node Quorum</span>
              <b className="text-primary font-mono font-bold">{status.quorum}</b>
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
            aria-label={collapsed ? "Open menu" : "Close menu"}
            title={collapsed ? "Open menu" : "Close menu"}
          >
            {collapsed ? "menu_open" : "menu_close"}
          </button>

          <div className="flex items-center gap-1 text-sm text-on-surface-variant">
            <span className="text-on-surface font-medium">Command Deck</span>
            <span>/</span>
            <span>{current.label}</span>
          </div>

          <div className="flex-1" />

          <div className="relative flex items-center">
            <input
              className="bg-surface-container-low border border-outline-variant/50 rounded-lg px-3 py-1.5 text-sm text-on-surface w-72 focus:outline-none focus:border-primary"
              placeholder="Search telemetry, hashes, IPs..."
              type="text"
            />
            <span className="absolute right-2.5 text-[10px] bg-surface-container px-1.5 py-0.5 rounded text-on-surface-variant font-mono font-medium">
              Ctrl+K
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button className="px-2.5 py-1 rounded bg-primary-container/20 text-primary text-xs font-mono font-semibold border border-primary/30">
              Operational
            </button>
          </div>

          <div className="relative">
            <span className="material-symbols-outlined text-on-surface-variant cursor-pointer">notifications</span>
            {alertCount > 0 && (
              <span className="absolute -top-1 -right-1 bg-error text-on-error text-[10px] w-4 h-4 rounded-full flex items-center justify-center font-bold">
                {alertCount > 99 ? "99+" : alertCount}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 pl-4 border-l border-outline-variant/30">
            <div className="w-8 h-8 rounded-full bg-primary flex items-center justify-center text-on-primary">
              <span className="material-symbols-outlined text-[18px]">person</span>
            </div>
            <div className="hidden xl:block">
              <div className="text-sm font-medium text-on-surface">{operator?.display_name ?? operator?.id ?? "—"}</div>
              <div className="text-xs text-on-surface-variant">{operator?.role ?? "UNAUTHENTICATED"}</div>
            </div>
          </div>
        </header>

        <main className="content">{children}</main>
      </div>
    </div>
  );
}

function navCount(route: string, s: ShellStatus): { n: number; alert: boolean } | null {
  if (route === "security" && s.openIncidents) return { n: s.openIncidents, alert: s.criticalIncidents > 0 };
  if (route === "approvals" && s.pendingApprovals) return { n: s.pendingApprovals, alert: false };
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
