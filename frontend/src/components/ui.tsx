import {
  createContext, useCallback, useContext, useEffect, useMemo, useRef, useState,
  type ReactNode,
} from "react";

/* ------------------------------------------------------------------ badges */

export type Tone = "ok" | "warn" | "crit" | "info" | "idle" | "high";

export function Badge({ tone = "idle", children, lg, title }: {
  tone?: Tone; children: ReactNode; lg?: boolean; title?: string;
}) {
  return <span className={`badge ${tone}`} title={title}>{children}</span>;
}

export function Dot({ tone = "idle", pulse, title }: {
  tone?: Tone; pulse?: boolean; title?: string;
}) {
  return <span className={`dot ${tone} ${pulse ? "pulse" : ""}`} title={title} aria-hidden />;
}

/* Maps backend status strings onto tones. Unknown values stay grey on purpose —
   the UI must never invent a severity it wasn't told about. */
const STATUS_TONE: Record<string, Tone> = {
  ACTIVE: "ok", VERIFIED: "ok", VALID: "ok", SEALED: "ok", ENCRYPTED: "ok",
  AUTHORIZED: "ok", VERIFIED_ASSOCIATION: "ok", CONFIRMED: "ok", PASS: "ok",
  MATCH: "ok", MATCHED: "ok", COMPLETED: "ok", COMPLETE: "ok", RESOLVED: "ok",
  CLOSED: "idle", HEALTHY: "ok", SYNCED: "ok", IN_SYNC: "ok", KEY_REVOKED: "ok",

  PENDING: "warn", PENDING_AUTHORIZATION: "warn", QUEUED: "warn", OFFLINE: "warn",
  DEGRADED: "warn", PARTIAL: "warn", PARTIAL_RECOVERY: "warn", ATTENTION: "warn",
  WARNING: "warn", WARN: "warn", AGING: "warn", INVESTIGATING: "warn",
  SUSPENDED: "warn", QUARANTINED: "warn", BREAK_GLASS_PENDING: "warn",

  REVOKED: "crit", REJECTED: "crit", FAILED: "crit", BLOCKED: "crit",
  DENIED: "crit", TAMPER_DETECTED: "crit", TAMPER: "crit", CRITICAL: "crit",
  BREACH: "crit", LOCKED: "crit", LOCKDOWN: "crit", EXPIRED: "crit",
  CRITICAL_EVENT: "crit", CONFIRMED_LEAK: "crit", DECRYPTED: "info",
  UNAVAILABLE: "idle", INACTIVE: "idle", IDLE: "idle", UNKNOWN: "idle",
};

export function statusTone(status: string | undefined | null): Tone {
  if (!status) return "idle";
  return STATUS_TONE[status.toUpperCase().replace(/[\s-]+/g, "_")] ?? "idle";
}

export function StatusBadge({ status, tone, lg }: { status?: string | null; tone?: Tone; lg?: boolean }) {
  if (status === undefined || status === null || status === "") return <span className="dim tiny">—</span>;
  return <Badge tone={tone ?? statusTone(status)} lg={lg}>{status}</Badge>;
}

export function SeverityBadge({ severity }: { severity?: string | null }) {
  if (!severity) return <span className="dim tiny">—</span>;
  const s = severity.toUpperCase();
  const tone: Tone = s === "CRITICAL" ? "crit" : s === "HIGH" ? "high" : s === "MEDIUM" ? "warn" : "info";
  return <Badge tone={tone}>{severity}</Badge>;
}

/* ------------------------------------------------------------- copy / hash */

export function CopyButton({ text, label = "copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  const timer = useRef<number>();
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch { /* clipboard unavailable */ }
      ta.remove();
    }
    setDone(true);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setDone(false), 1300);
  };

  return (
    <button
      className={`copy-btn ${done ? "done" : ""}`}
      onClick={copy}
      title={done ? "Copied" : label}
      aria-label={done ? "Copied to clipboard" : label}
    >
      {done ? "✓" : "⧉"}
    </button>
  );
}

/** Truncated hash with full value on hover. */
export function Hash({ value, chars = 16, copy = true }: { value?: string | null; chars?: number; copy?: boolean }) {
  if (!value) return <span className="dim tiny">—</span>;
  const short = value.length > chars ? `${value.slice(0, chars)}…` : value;
  return (
    <span className="hash" title={value}>
      <span>{short}</span>
      {copy ? <CopyButton text={value} /> : null}
    </span>
  );
}

export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return <span className="mono" title={title}>{children}</span>;
}

/* --------------------------------------------------------------- tooltip */

export function Tip({ children, text }: { children: ReactNode; text: string }) {
  return (
    <span className="tip">
      {children}
      <span className="tip-body" role="tooltip">{text}</span>
    </span>
  );
}

/* ---------------------------------------------------------------- panel */

export function Panel({ title, actions, children, tone, flush, className = "" }: {
  title?: string; actions?: ReactNode; children: ReactNode;
  tone?: "ok" | "crit" | "warn"; flush?: boolean; className?: string;
}) {
  return (
    <section className={`panel ${tone ? `accent-${tone}` : ""} ${className}`}>
      {title || actions ? (
        <header className="panel-head">
          <h3>{title}</h3>
          {actions ? <div className="flex gap-sm">{actions}</div> : null}
        </header>
      ) : null}
      <div className={`panel-body ${flush ? "flush" : ""}`}>{children}</div>
    </section>
  );
}

export function Metric({ label, value, sub, tone, foot, small }: {
  label: string; value: ReactNode; sub?: ReactNode;
  tone?: "ok" | "warn" | "crit" | "info" | "high" | "idle"; foot?: ReactNode; small?: boolean;
}) {
  return (
    <div className={`metric ${tone && tone !== "high" && tone !== "idle" ? tone : ""}`}>
      <div className="k">{label}</div>
      <div className={`v ${small ? "sm" : ""}`}>{value}</div>
      {sub ? <div className="s">{sub}</div> : null}
      {foot ? <div className="foot">{foot}</div> : null}
    </div>
  );
}

/* ------------------------------------------------------------- data table */

export type Column<T> = {
  key: string;
  head: string;
  render: (row: T) => ReactNode;
  num?: boolean;
  width?: number | string;
};

export function DataTable<T>({ columns, rows, empty, onRow, selected, rowClass, maxHeight }: {
  columns: Column<T>[];
  rows: T[];
  empty?: ReactNode;
  onRow?: (row: T) => void;
  selected?: (row: T) => boolean;
  rowClass?: (row: T) => string | undefined;
  maxHeight?: number;
}) {
  if (!rows.length) return <>{empty ?? <EmptyState icon="◍" title="No records" sub="Nothing to show for the current filters." />}</>;

  return (
    <div className="table-wrap" style={maxHeight ? { maxHeight, overflowY: "auto" } : undefined}>
      <table className="tbl">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={c.num ? "num" : ""} style={c.width ? { width: c.width } : undefined}>
                {c.head}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr
              key={i}
              className={`${onRow ? "clickable" : ""} ${selected?.(row) ? "sel" : ""} ${rowClass?.(row) ?? ""}`}
              onClick={onRow ? () => onRow(row) : undefined}
            >
              {columns.map((c) => (
                <td key={c.key} className={c.num ? "num mono" : ""}>{c.render(row)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ------------------------------------------------------------------ states */

export function LoadingState({ label = "Loading", detail }: { label?: string; detail?: string }) {
  return (
    <div className="running" role="status" aria-live="polite">
      <Dot tone="info" pulse />
      <span className="nowrap">{label}</span>
      <span className="bar-ind"><i /></span>
      {detail ? <span className="tiny dim nowrap">{detail}</span> : null}
    </div>
  );
}

export function EmptyState({ icon = "◍", title, sub, action }: {
  icon?: string; title: string; sub?: ReactNode; action?: ReactNode;
}) {
  return (
    <div className="state">
      <div className="ico" aria-hidden>{icon}</div>
      <div className="t">{title}</div>
      {sub ? <div className="s">{sub}</div> : null}
      {action}
    </div>
  );
}

/** Renders an API error with the real status code and message — never swallows it. */
export function ErrorNotice({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const e = error as { status?: number; message?: string } | string | null;
  const status = typeof e === "object" && e ? e.status : undefined;
  const msg = typeof e === "string" ? e : e?.message;
  const body = msg || "The backend did not return a usable response.";

  return (
    <div className="notice crit" role="alert">
      <span className="ico" aria-hidden>⚠</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <b>{status ? `Request failed · HTTP ${status}` : "Request failed"}</b>
        <div style={{ marginTop: 3, overflowWrap: "anywhere" }}>{body}</div>
      </div>
      {onRetry ? <button className="btn sm" onClick={onRetry}>Retry</button> : null}
    </div>
  );
}

/** 401/403 boundary — the operator's token or role is not sufficient. */
export function Unauthorized({ error, onLogin }: { error: unknown; onLogin: () => void }) {
  const e = error as { status?: number; message?: string } | null;
  const forbidden = e?.status === 403;
  return (
    <EmptyState
      icon="⛔"
      title={forbidden ? "Insufficient clearance" : "Session expired"}
      sub={
        <>
          {forbidden
            ? "Your role does not carry the permission this endpoint requires. Ask a Commander or Administrator to grant it — the UI cannot elevate itself."
            : <>The access token is no longer valid. <span className="mono">{e?.message ?? "HTTP 401"}</span></>}
        </>
      }
      action={<button className="btn primary" onClick={onLogin}>{forbidden ? "Re-authenticate" : "Sign in again"}</button>}
    />
  );
}

export function Notice({ tone = "idle", title, children }: {
  tone?: Tone; title?: string; children: ReactNode;
}) {
  const icon = tone === "ok" ? "✓" : tone === "crit" ? "⚠" : tone === "warn" ? "▲" : tone === "info" ? "ℹ" : "·";
  return (
    <div className={`notice ${tone}`} role={tone === "crit" ? "alert" : undefined}>
      <span className="ico" aria-hidden>{icon}</span>
      <div style={{ minWidth: 0 }}>
        {title ? <b>{title}</b> : null}
        <div>{children}</div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------- verification steps */

export type StepState = "pass" | "fail" | "partial" | "unknown";

export function VerificationStep({ state, name, detail, right }: {
  state: StepState; name: string; detail?: ReactNode; right?: ReactNode;
}) {
  const mark = state === "pass" ? "✓" : state === "fail" ? "✕" : state === "partial" ? "!" : "?";
  return (
    <div className={`vstep ${state}`}>
      <span className="mark" aria-label={state}>{mark}</span>
      <div style={{ minWidth: 0 }}>
        <div className="nm">{name}</div>
        {detail ? <div className="dt">{detail}</div> : null}
      </div>
      <div className="st">{right ?? <StatusBadge status={state === "pass" ? "PASS" : state === "fail" ? "FAIL" : state === "partial" ? "PARTIAL" : "UNKNOWN"} />}</div>
    </div>
  );
}

export function Pipeline({ children, running, label }: { children: ReactNode; running?: boolean; label?: string }) {
  if (running) return <LoadingState label={label ?? "Running verification pipeline"} />;
  return <div className="pipeline">{children}</div>;
}

/* --------------------------------------------------------------- timeline */

export type TimelineItem = {
  id: string;
  time?: string | null;
  title: string;
  detail?: ReactNode;
  right?: ReactNode;
  severity?: string | null;
};

export function Timeline({ items }: { items: TimelineItem[] }) {
  if (!items.length) return <EmptyState icon="◷" title="No events yet" sub="Nothing has been recorded against this scope." />;
  return (
    <div className="timeline">
      {items.map((it) => (
        <div key={it.id} className={`tl-item ${it.severity ? `sev-${it.severity.toUpperCase()}` : ""}`}>
          <div className="tl-time">{formatTime(it.time)}</div>
          <div className="tl-body">
            <div className="hd">
              <span className="ti">{it.title}</span>
              {it.severity ? <SeverityBadge severity={it.severity} /> : null}
              {it.right}
            </div>
            {it.detail ? <div className="de">{it.detail}</div> : null}
          </div>
        </div>
      ))}
    </div>
  );
}

export function formatTime(t?: string | null): string {
  if (!t) return "—";
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) return String(t).slice(11, 19) || "—";
  return d.toISOString().slice(11, 19);
}

export function formatDateTime(t?: string | null): string {
  if (!t) return "—";
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) return String(t);
  return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

/* ----------------------------------------------------------------- filters */

export function SearchInput({ value, onChange, placeholder = "Search", width }: {
  value: string; onChange: (v: string) => void; placeholder?: string; width?: number | string;
}) {
  return (
    <div className="search-box" style={width ? { width } : undefined}>
      <input
        className="inp"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        aria-label={placeholder}
      />
    </div>
  );
}

export function FilterChips<T extends string>({ options, value, onChange }: {
  options: readonly { value: T; label: string; count?: number }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="chips" role="group">
      {options.map((o) => (
        <button
          key={o.value}
          className={`chip ${value === o.value ? "on" : ""}`}
          onClick={() => onChange(o.value)}
          aria-pressed={value === o.value}
        >
          {o.label}
          {o.count !== undefined ? <span className="n">{o.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ modal */

export function Modal({ title, sub, onClose, children, footer, wide, danger }: {
  title: string; sub?: ReactNode; onClose: () => void;
  children: ReactNode; footer?: ReactNode; wide?: boolean; danger?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [onClose]);

  return (
    <div className="scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`modal ${wide ? "wide" : ""} ${danger ? "danger" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <header className="modal-head">
          <div style={{ flex: 1 }}>
            <h3>{title}</h3>
            {sub ? <p>{sub}</p> : null}
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">✕</button>
        </header>
        <div className="modal-body">{children}</div>
        {footer ? <div className="modal-foot">{footer}</div> : null}
      </div>
    </div>
  );
}

export function Drawer({ title, sub, onClose, children, actions }: {
  title: string; sub?: ReactNode; onClose: () => void; children: ReactNode; actions?: ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={title}>
        <header className="drawer-head">
          <div style={{ minWidth: 0 }}>
            <h3 style={{ margin: 0, fontSize: 14, letterSpacing: 1 }}>{title}</h3>
            {sub ? <div className="tiny muted" style={{ marginTop: 3 }}>{sub}</div> : null}
          </div>
          <div className="flex gap-sm">
            {actions}
            <button className="icon-btn" onClick={onClose} aria-label="Close">✕</button>
          </div>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </>
  );
}

/* ------------------------------------------------------------------ toasts */

type Toast = { id: number; tone: Tone; title: string; detail?: ReactNode };

const ToastCtx = createContext<{
  push: (t: Omit<Toast, "id">) => void;
  success: (title: string, detail?: ReactNode) => void;
  failure: (title: string, detail?: ReactNode) => void;
  info: (title: string, detail?: ReactNode) => void;
}>({ push: () => {}, success: () => {}, failure: () => {}, info: () => {} });

export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const seq = useRef(0);

  const remove = useCallback((id: number) => setItems((p) => p.filter((t) => t.id !== id)), []);

  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = ++seq.current;
    setItems((p) => [...p.slice(-3), { ...t, id }]);
    window.setTimeout(() => remove(id), t.tone === "crit" ? 9000 : 5000);
  }, [remove]);

  const value = useMemo(() => ({
    push,
    success: (title: string, detail?: ReactNode) => push({ tone: "ok", title, detail }),
    failure: (title: string, detail?: ReactNode) => push({ tone: "crit", title, detail }),
    info: (title: string, detail?: ReactNode) => push({ tone: "info", title, detail }),
  }), [push]);

  return (
    <ToastCtx.Provider value={value}>
      {children}
      <div className="toasts" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`toast ${t.tone}`} onClick={() => remove(t.id)} role="status">
            <span className="ico" aria-hidden>
              {t.tone === "ok" ? "✓" : t.tone === "crit" ? "⚠" : t.tone === "warn" ? "▲" : "ℹ"}
            </span>
            <div style={{ minWidth: 0 }}>
              <b>{t.title}</b>
              {t.detail ? <div className="d">{t.detail}</div> : null}
            </div>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/* ------------------------------------------------------------- data loader */

/**
 * Minimal fetch-on-mount hook with explicit loading/error/data states.
 * Every page uses this so no screen can silently render a blank panel.
 */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fn()
      .then((d) => { if (!cancelled) setData(d); })
      .catch((e) => { if (!cancelled) setError(e); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, error, loading, reload, setData };
}

/* ------------------------------------------------------------------ labels */

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="field">
      <label>{label}{hint ? <span className="dim"> · {hint}</span> : null}</label>
      {children}
    </div>
  );
}

export function PageHead({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {sub ? <p>{sub}</p> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function Tabs({ tabs, active, onPick }: {
  tabs: { id: string; label: string }[];
  active: string;
  onPick: (id: string) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={t.id === active}
          className={`tab ${t.id === active ? "on" : ""}`}
          onClick={() => onPick(t.id)}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}
