import { useState } from "react";
import { api, endpoints, type LoginResponse } from "../api";
import { Badge, ErrorNotice, Notice } from "../components/ui";

const DEMO: { id: string; password: string; role: string; views: string }[] = [
  { id: "COMMANDER-001", password: "Commander!2026", role: "COMMANDER", views: "command · documents · events · incidents · approvals · ledger · audit · intelligence" },
  { id: "SECURITY-001", password: "Security!2026", role: "SECURITY_OFFICER", views: "events · incidents · devices · approvals · ledger · audit · lab" },
  { id: "ADMIN-001", password: "Admin!2026", role: "DOCUMENT_ADMIN", views: "documents · recipients · devices · approvals · audit" },
  { id: "RECIPIENT-001", password: "Recipient1!2026", role: "RECIPIENT", views: "documents · own sessions" },
  { id: "RECIPIENT-002", password: "Recipient2!2026", role: "RECIPIENT", views: "documents · own sessions" },
  { id: "INVESTIGATOR-001", password: "Investigator!2026", role: "INVESTIGATOR", views: "forensics · investigations · watermark probe · ledger" },
  { id: "AUDITOR-001", password: "Auditor!2026", role: "AUDITOR", views: "read-only: ledger verify · audit · evidence" },
  { id: "LEDGER-001", password: "Ledger!2026", role: "LEDGER_OPERATOR", views: "ledger · nodes · chain verification" },
];

export function Login({ onAuthenticated }: { onAuthenticated: (token: string) => void }) {
  const [id, setId] = useState("COMMANDER-001");
  const [password, setPassword] = useState("Commander!2026");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const body = await api.post<LoginResponse>(endpoints.login, {
        recipient_id: id.trim(),
        password,
      });
      onAuthenticated(body.token);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-left">
          <h1>SENTINEL</h1>
          <div className="tag">Document Security &amp; Leak Forensics</div>

          <div className="claim">
            <b>What this system claims</b>
            If a document copy leaves the system, the copy itself can be tied — cryptographically — to the exact
            decryption session and key holder that produced it. The original never leaves, and every step is written
            to a replicated ledger.
          </div>

          <div className="stack" style={{ gap: 7 }}>
            <Fact k="Key exchange" v="ML-KEM-768 (post-quantum)" />
            <Fact k="Signatures" v="ML-DSA-65 (post-quantum)" />
            <Fact k="Content cipher" v="AES-256-GCM" />
            <Fact k="Attribution" v="Session-keyed DCT watermark" />
            <Fact k="Ledger" v="3 replicas, quorum of 2" />
            <Fact k="Deployment" v="Local process, loopback only" />
          </div>

          <div className="tiny dim" style={{ marginTop: 18, lineHeight: 1.6 }}>
            A working prototype, not a production deployment. Recovery proves an association with a session — it is
            not proof that a named person leaked a document.
          </div>
        </div>

        <form className="login-right" onSubmit={submit}>
          <div>
            <h2 style={{ margin: "0 0 3px", fontSize: 14, letterSpacing: 1.4 }}>Authenticate</h2>
            <div className="tiny muted">Credentials are checked by the backend, never in the browser.</div>
          </div>

          <div className="field">
            <label htmlFor="login-id">Recipient ID</label>
            <input
              id="login-id" className="inp" value={id} autoComplete="username"
              onChange={(e) => setId(e.target.value)}
            />
          </div>

          <div className="field">
            <label htmlFor="login-pw">Password</label>
            <input
              id="login-pw" className="inp" type="password" value={password} autoComplete="current-password"
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {error ? <ErrorNotice error={error} /> : null}

          <button className="btn primary block" type="submit" disabled={busy || !id || !password}>
            {busy ? "Authenticating…" : "→ Enter console"}
          </button>

          <div className="hr" />

          <div className="flex-between">
            <span className="tiny dim" style={{ letterSpacing: 1.2 }}>DEMONSTRATION IDENTITIES</span>
            <Badge tone="info">{DEMO.length}</Badge>
          </div>

          <div className="stack" style={{ gap: 4 }}>
            {DEMO.map((d) => (
              <button
                type="button" key={d.id}
                className={`demo-row ${id === d.id ? "on" : ""}`}
                onClick={() => { setId(d.id); setPassword(d.password); setError(null); }}
              >
                <span style={{ minWidth: 0 }}>
                  <b>{d.id}</b>
                  <span>{d.role}</span>
                  <span className="dim">{d.views}</span>
                </span>
                {id === d.id ? <Badge tone="info">SELECTED</Badge> : null}
              </button>
            ))}
          </div>

          <Notice tone="warn" title="Navigation follows your real permissions">
            The sidebar only offers views your role can actually open, because the backend enforces them. Signing in
            as a recipient genuinely removes commander actions.
          </Notice>
        </form>
      </div>
    </div>
  );
}

function Fact({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex-between">
      <span className="tiny dim" style={{ letterSpacing: 0.8 }}>{k.toUpperCase()}</span>
      <span className="mono tiny" style={{ color: "var(--tx-2)" }}>{v}</span>
    </div>
  );
}
