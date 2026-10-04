import { useMemo, useState } from "react";
import {
  api, endpoints,
  type DeviceRow, type DevicesResponse, type Identity, type RecipientsResponse,
} from "../api";
import {
  Badge, DataTable, Drawer, EmptyState, ErrorNotice, FilterChips, LoadingState, Metric,
  Modal, Notice, PageHead, Panel, SearchInput, StatusBadge, Unauthorized, useAsync, useToast,
} from "../components/ui";
import { IdentBadge } from "../components/layout";

/* =========================================================== recipients */

export function Recipients() {
  const people = useAsync<RecipientsResponse>(() => api.get<RecipientsResponse>(endpoints.recipients), []);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"all" | "active" | "suspended" | "revoked">("all");
  const [open, setOpen] = useState<Identity | null>(null);

  const rows = people.data?.identities ?? [];
  const counts = useMemo(() => ({
    all: rows.length,
    active: rows.filter((r) => r.status === "ACTIVE").length,
    suspended: rows.filter((r) => r.status === "SUSPENDED").length,
    revoked: rows.filter((r) => r.status === "REVOKED").length,
  }), [rows]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (filter !== "all" && r.status !== filter.toUpperCase()) return false;
      if (!needle) return true;
      return [r.recipient_id, r.display_name, r.role, r.unit, r.email, r.clearance_label]
        .some((v) => v?.toLowerCase().includes(needle));
    });
  }, [rows, q, filter]);

  if (people.loading && !people.data) return <LoadingState label="Loading identity directory" detail="GET /recipients" />;
  if (people.error) {
    const st = (people.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={people.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={people.error} onRetry={people.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Recipients"
        sub="Every holder of a post-quantum key pair. Revocation and key invalidation are recorded on the ledger, so a revoked holder cannot decrypt even with an older session."
        actions={
          <>
            <Badge tone="info">{rows.length} IDENTITIES</Badge>
            <button className="btn" onClick={people.reload} disabled={people.loading}>
              {people.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      <div className="grid g4">
        <Metric label="Active" value={counts.active} tone="ok" sub="may request decryption" />
        <Metric label="Suspended" value={counts.suspended} tone={counts.suspended ? "warn" : "ok"} sub="temporarily blocked" />
        <Metric label="Revoked" value={counts.revoked} tone={counts.revoked ? "crit" : "ok"} sub="keys invalidated on ledger" />
        <Metric label="Directory" value={rows.length} tone="info" sub="identities known to the system" />
      </div>

      <Panel flush>
        <div className="panel-body" style={{ borderBottom: "1px solid var(--hair)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <SearchInput value={q} onChange={setQ} placeholder="Search name, ID, role, unit, email…" width={320} />
          <FilterChips
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All", count: counts.all },
              { value: "active", label: "Active", count: counts.active },
              { value: "suspended", label: "Suspended", count: counts.suspended },
              { value: "revoked", label: "Revoked", count: counts.revoked },
            ]}
          />
          <span className="tiny dim" style={{ marginLeft: "auto" }}>{filtered.length} of {rows.length} shown</span>
        </div>

        <DataTable
          rows={filtered}
          onRow={(r) => setOpen(r)}
          empty={<EmptyState icon="◍" title="No identities match" sub={q ? `Nothing matches “${q}”.` : "No identity carries this status."} />}
          columns={[
            { key: "n", head: "Name", render: (r) => (
              <span className="stack" style={{ gap: 2 }}>
                <span>{r.display_name}</span>
                <span className="tiny dim">{r.unit}</span>
              </span>
            ) },
            { key: "id", head: "Recipient ID", render: (r) => <IdentBadge id={r.recipient_id} kind="recipient" /> },
            { key: "r", head: "Role", render: (r) => <Badge tone="info">{r.role}</Badge> },
            { key: "c", head: "Clearance", num: true, render: (r) => (
              <span title={r.clearance_label}>{r.clearance}</span>
            ) },
            { key: "s", head: "Status", render: (r) => <StatusBadge status={r.status} /> },
            { key: "l", head: "Last login", render: (r) => <span className="tiny dim">{r.last_login_at?.slice(0, 19).replace("T", " ") ?? "never"}</span> },
          ]}
        />
      </Panel>

      {open ? (
        <RecipientDrawer
          person={open}
          onClose={() => setOpen(null)}
          onDone={() => people.reload()}
        />
      ) : null}
    </div>
  );
}

function RecipientDrawer({ person, onClose, onDone }: {
  person: Identity; onClose: () => void; onDone: () => void;
}) {
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<null | "suspend" | "revoke" | "keys">(null);

  const act = async () => {
    if (!confirm) return;
    const path = confirm === "suspend" ? endpoints.recipientSuspend(person.recipient_id)
      : confirm === "revoke" ? endpoints.recipientRevoke(person.recipient_id)
      : endpoints.recipientRevokeKeys(person.recipient_id);
    setBusy(confirm);
    try {
      await api.post(path, {});
      toast.success(
        `${confirm === "suspend" ? "Suspension" : confirm === "revoke" ? "Revocation" : "Key revocation"} recorded`,
        `${person.recipient_id} · written to the audit trail and the ledger.`,
      );
      setConfirm(null);
      onDone();
    } catch (e) {
      toast.failure("Action refused", String((e as Error).message));
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <Drawer title={person.display_name} sub={<IdentBadge id={person.recipient_id} kind="recipient" />} onClose={onClose}>
        <div className="stack">
          <div className="flex wrap gap-sm">
            <StatusBadge status={person.status} lg />
            <Badge tone="info" lg>{person.role}</Badge>
            <Badge tone={person.clearance >= 4 ? "crit" : person.clearance >= 3 ? "high" : "idle"} lg>
              CLEARANCE {person.clearance} · {person.clearance_label}
            </Badge>
          </div>

          <Panel title="Identity record">
            <dl className="kv">
              <dt>Recipient ID</dt><dd>{person.recipient_id}</dd>
              <dt>Display name</dt><dd>{person.display_name}</dd>
              <dt>Email</dt><dd>{person.email}</dd>
              <dt>Role</dt><dd>{person.role}</dd>
              <dt>Unit</dt><dd>{person.unit}</dd>
              <dt>Clearance</dt><dd>{person.clearance} — {person.clearance_label}</dd>
              <dt>Created</dt><dd>{person.created_at}</dd>
              <dt>Last login</dt><dd>{person.last_login_at ?? "never"}</dd>
              <dt>Revoked at</dt><dd>{person.revoked_at ?? "—"}</dd>
              <dt>Revocation reason</dt><dd>{person.revocation_reason ?? "—"}</dd>
            </dl>
          </Panel>

          <Panel title="Actions" tone={person.status === "ACTIVE" ? undefined : "warn"}>
            <Notice tone="warn" title="These change authorisation state">
              The backend enforces clearance and dual control. Nothing here succeeds silently — a refusal raises an
              error and is shown exactly as the backend phrased it.
            </Notice>
            <div className="pill-row mt">
              <button className="btn sm warn" disabled={person.status !== "ACTIVE" || busy !== null}
                onClick={() => setConfirm("suspend")}>Suspend</button>
              <button className="btn sm warn" disabled={person.status === "REVOKED" || busy !== null}
                onClick={() => setConfirm("keys")}>Revoke keys only</button>
              <button className="btn sm danger" disabled={person.status === "REVOKED" || busy !== null}
                onClick={() => setConfirm("revoke")}>Revoke identity</button>
            </div>
          </Panel>
        </div>
      </Drawer>

      {confirm ? (
        <Modal
          title={confirm === "suspend" ? "Suspend identity" : confirm === "revoke" ? "Revoke identity" : "Revoke key material"}
          sub={`${person.display_name} · ${person.recipient_id}`}
          onClose={() => setConfirm(null)}
          danger={confirm !== "suspend"}
          footer={
            <>
              <button className="btn" onClick={() => setConfirm(null)}>Cancel</button>
              <button className={`btn ${confirm === "suspend" ? "warn" : "danger"}`} onClick={act} disabled={busy !== null}>
                {busy ? "Submitting…" : "Confirm"}
              </button>
            </>
          }
        >
          <Notice tone={confirm === "suspend" ? "warn" : "crit"} title="Recorded on the ledger">
            {confirm === "suspend"
              ? "The holder can no longer request new decryption authorisations. Existing session records are untouched."
              : confirm === "keys"
                ? "Key wraps for this identity are invalidated, so already-issued sessions stop decrypting. The revocation is anchored on the ledger."
                : "The identity is permanently revoked and its key material invalidated. The console cannot undo this."}
          </Notice>
        </Modal>
      ) : null}
    </>
  );
}

/* ============================================================== devices */

export function Devices() {
  const toast = useToast();
  const devices = useAsync<DevicesResponse>(() => api.get<DevicesResponse>(endpoints.devices), []);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("all");
  const [busy, setBusy] = useState<string | null>(null);

  const rows = devices.data?.devices ?? [];
  const trustStates = devices.data?.trust_states ?? ["TRUSTED", "UNVERIFIED", "REVOKED"];

  const counts = useMemo(() => {
    const m: Record<string, number> = { all: rows.length };
    for (const t of trustStates) m[t] = rows.filter((r) => r.trust_state === t).length;
    return m;
  }, [rows, trustStates]);

  const revokedCount = rows.filter((r) => r.status === "REVOKED").length;

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (filter !== "all" && r.trust_state !== filter) return false;
      if (!needle) return true;
      return [r.device_id, r.recipient_id, r.device_name, r.trust_state, r.trust_note ?? ""]
        .some((v) => v.toLowerCase().includes(needle));
    });
  }, [rows, q, filter]);

  const act = async (device: DeviceRow, revoke: boolean) => {
    setBusy(device.device_id);
    try {
      await api.post(
        revoke ? endpoints.deviceRevoke(device.device_id) : endpoints.deviceTrust(device.device_id), {},
      );
      toast.success(revoke ? "Device revoked" : "Device re-registered", device.device_id);
      devices.reload();
    } catch (e) {
      toast.failure("Action refused", String((e as Error).message));
    } finally {
      setBusy(null);
    }
  };

  if (devices.loading && !devices.data) return <LoadingState label="Loading device registry" detail="GET /devices" />;
  if (devices.error) {
    const st = (devices.error as { status?: number }).status;
    return st === 401 || st === 403
      ? <Unauthorized error={devices.error} onLogin={() => window.location.reload()} />
      : <ErrorNotice error={devices.error} onRetry={devices.reload} />;
  }

  return (
    <div className="stack">
      <PageHead
        title="Devices"
        sub="A decryption session is bound to one registered device. Revocation is enforced on the very next request and recorded on the ledger."
        actions={
          <>
            <Badge tone="info">{rows.length} DEVICES</Badge>
            <button className="btn" onClick={devices.reload} disabled={devices.loading}>
              {devices.loading ? "Refreshing…" : "↻ Refresh"}
            </button>
          </>
        }
      />

      {revokedCount > 0 ? (
        <Notice tone="warn" title={`${revokedCount} device(s) revoked`}>
          Sessions issued to a revoked device can no longer be authorised. Historical session records stay intact for
          audit.
        </Notice>
      ) : null}

      <div className="grid g4">
        <Metric label="Registered" value={rows.length} tone="info" />
        {trustStates.slice(0, 3).map((t) => (
          <Metric
            key={t}
            label={t.replace(/_/g, " ").toLowerCase()}
            value={counts[t] ?? 0}
            tone={t === "REVOKED" ? (counts[t] ? "crit" : "ok") : t === "TRUSTED" ? "ok" : counts[t] ? "warn" : "ok"}
          />
        ))}
      </div>

      <Panel flush>
        <div className="panel-body" style={{ borderBottom: "1px solid var(--hair)", display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <SearchInput value={q} onChange={setQ} placeholder="Search device, owner, trust state…" width={320} />
          <FilterChips
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "All", count: rows.length },
              ...trustStates.map((t) => ({
                value: t, label: t.replace(/_/g, " ").toLowerCase(), count: counts[t] ?? 0,
              })),
            ]}
          />
          <span className="tiny dim" style={{ marginLeft: "auto" }}>{filtered.length} of {rows.length} shown</span>
        </div>

        <DataTable
          rows={filtered}
          maxHeight={620}
          empty={<EmptyState icon="▣" title="No devices match" sub={q ? `Nothing matches “${q}”.` : "No device carries this trust state."} />}
          columns={[
            { key: "i", head: "Device ID", render: (r) => <IdentBadge id={r.device_id} kind="device" /> },
            { key: "l", head: "Device", render: (r) => r.device_name },
            { key: "o", head: "Owner", render: (r) => <span className="mono">{r.recipient_id}</span> },
            { key: "t", head: "Trust", render: (r) => <StatusBadge status={r.trust_state} /> },
            { key: "s", head: "Status", render: (r) => <StatusBadge status={r.status} /> },
            { key: "n", head: "Trust note", render: (r) => (
              <span className="tiny muted" style={{ maxWidth: 260, display: "block" }}>{r.trust_note ?? "—"}</span>
            ) },
            { key: "seen", head: "Last seen", render: (r) => <span className="tiny dim">{r.last_seen_at?.slice(0, 19).replace("T", " ") ?? "never"}</span> },
            {
              key: "a", head: "Action", render: (r) => (
                r.status === "REVOKED" ? (
                  <button className="btn sm" disabled={busy === r.device_id} onClick={() => act(r, false)}>Re-register</button>
                ) : (
                  <button className="btn sm danger" disabled={busy === r.device_id} onClick={() => act(r, true)}>Revoke</button>
                )
              ),
            },
          ]}
        />
      </Panel>

      {devices.data?.limitation ? (
        <Notice tone="warn" title="Declared limitation">{devices.data.limitation}</Notice>
      ) : null}
    </div>
  );
}
