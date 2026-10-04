import { useCallback, useEffect, useState } from "react";
import {
  api, endpoints, setToken,
  type AiHealth, type Dashboard, type Health, type LockdownState, type WhoAmI,
} from "./api";
import { NAV, Shell, navVisible, type LockdownInfo, type Operator, type ShellStatus } from "./components/layout";
import { EmptyState, ToastProvider } from "./components/ui";
import { Login } from "./pages/Login";
import { CommandCenter } from "./pages/CommandCenter";
import { Documents } from "./pages/Documents";
import { Sessions } from "./pages/Sessions";
import { Approvals } from "./pages/Approvals";
import { ForensicsView, IdentityView, LedgerView, OversightView, SecurityView } from "./pages/views";

export default function App() {
  const [operator, setOperator] = useState<Operator | null>(null);
  const [page, setPage] = useState("command");
  const [status, setStatus] = useState<ShellStatus>({
    postureScore: null,
    postureRating: "",
    quorum: "—",
    openIncidents: 0,
    criticalIncidents: 0,
    pendingApprovals: 0,
    systemStatus: "CHECKING",
    aiStatus: "CHECKING",
  });
  const [lockdown, setLockdown] = useState<LockdownInfo | null>(null);

  const refreshStatus = useCallback(async () => {
    const [health, ai] = await Promise.all([
      api.get<Health>(endpoints.health).catch(() => null),
      api.get<AiHealth>(endpoints.aiHealth).catch(() => null),
    ]);

    setStatus((prev) => ({ ...prev, systemStatus: health?.status ?? "UNREACHABLE", aiStatus: ai?.status ?? "UNKNOWN" }));

    // The dashboard needs commander.dashboard, which not every role holds, so a
    // refusal here is expected and simply leaves the counters at zero.
    try {
      const dash = await api.get<Dashboard>(endpoints.commander);
      setStatus({
        postureScore: dash.security_posture?.score ?? null,
        postureRating: dash.security_posture?.rating ?? "",
        quorum: `${dash.ledger_health?.nodes?.length ?? 0} nodes`,
        openIncidents: dash.kpis?.critical_incidents ?? 0,
        criticalIncidents: dash.kpis?.critical_incidents ?? 0,
        pendingApprovals: dash.kpis?.pending_approvals ?? 0,
        systemStatus: health?.status ?? "UNKNOWN",
        aiStatus: ai?.status ?? "UNKNOWN",
      });
    } catch {
      /* role cannot read the commander dashboard; the shell still works */
    }
  }, []);

  const refreshLockdown = useCallback(async () => {
    try {
      const body = await api.get<LockdownState>(endpoints.lockdown);
      setLockdown({
        active: body.lockdown_active,
        reason: body.lockdown_reason,
        activated_at: body.lockdown_activated_at,
      });
    } catch {
      setLockdown(null);
    }
  }, []);

  const loadIdentity = useCallback(async () => {
    const me = await api.get<WhoAmI>(endpoints.whoami);
    setOperator({
      id: me.identity.recipient_id,
      display_name: me.identity.display_name,
      role: me.identity.role,
      unit: me.identity.unit,
      clearance: me.identity.clearance,
      permissions: me.permissions,
    });
    const reachable = NAV.find((n) => navVisible(n, me.permissions));
    if (reachable) setPage(reachable.id);
  }, []);

  useEffect(() => {
    if (!operator) return;
    refreshStatus();
    refreshLockdown();
    const timer = window.setInterval(refreshStatus, 30_000);
    return () => window.clearInterval(timer);
  }, [operator, refreshStatus, refreshLockdown]);

  const authenticate = (token: string) => {
    setToken(token);
    loadIdentity().catch((e) => {
      setToken(null);
      setOperator(null);
      window.alert(`The issued token was rejected by the backend: ${String(e)}`);
    });
  };

  const signOut = async () => {
    try {
      await api.post(endpoints.logout, { reason: "Signed out from the command terminal" });
    } catch {
      // A refused logout must not trap the operator in the console: tokens are
      // short-lived and every sensitive call is re-authorised from live state.
    }
    setToken(null);
    setOperator(null);
    setPage("command");
    setLockdown(null);
  };

  if (!operator) {
    return (
      <ToastProvider>
        <Login onAuthenticated={authenticate} />
      </ToastProvider>
    );
  }

  return (
    <ToastProvider>
      <Shell
        page={page}
        operator={operator}
        status={status}
        lockdown={lockdown}
        onNavigate={setPage}
        onLogout={signOut}
      >
        <View
          page={page}
          permissions={operator.permissions}
          onNavigate={setPage}
          onLockdownChanged={refreshLockdown}
        />
      </Shell>
    </ToastProvider>
  );
}

function View({ page, permissions, onNavigate, onLockdownChanged }: {
  page: string; permissions: string[]; onNavigate: (id: string) => void; onLockdownChanged: () => void;
}) {
  switch (page) {
    case "documents": return <Documents />;
    case "sessions": return <Sessions />;
    case "identity": return <IdentityView permissions={permissions} />;
    case "approvals": return <Approvals />;
    case "forensics": return <ForensicsView permissions={permissions} />;
    case "security": return <SecurityView permissions={permissions} />;
    case "ledger": return <LedgerView permissions={permissions} />;
    case "oversight": return <OversightView permissions={permissions} />;
    case "command":
      return <CommandCenter onNavigate={onNavigate} onLockdownChanged={onLockdownChanged} />;
    default:
      return (
        <EmptyState
          icon="⛔"
          title="That view is not available to your role"
          sub="Your identity does not hold the permission this view requires. Sign in as an identity that does."
        />
      );
  }
}
