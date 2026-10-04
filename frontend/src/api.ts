/**
 * Typed client for the local SENTINEL API.
 *
 * Every call is relative, so the UI can only ever reach the process serving it.
 * The authorisation token is held in memory only; nothing sensitive is written
 * to local storage.
 *
 * Response shapes live in ./types and were taken from the running backend rather
 * than guessed — `scripts/ui_contract_probe.py` prints them.
 */

export * from "./types";

export type Token = string;

let bearer: Token | null = null;

export function setToken(token: Token | null) {
  bearer = token;
}

export function hasToken() {
  return bearer !== null;
}

export class ApiError extends Error {
  code: string;
  status: number;
  detail: string;

  constructor(status: number, code: string, plain: string, detail: string) {
    super(plain);
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string> | undefined),
  };
  if (bearer) headers.Authorization = `Bearer ${bearer}`;

  const response = await fetch(path, { ...init, headers });
  const text = await response.text();
  let body: unknown = {};
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { error: { message: text.slice(0, 300) } };
    }
  }

  if (!response.ok) {
    const error = (body as { error?: { code?: string; message?: string; detail?: string } }).error ?? {};
    throw new ApiError(
      response.status,
      error.code ?? "UNKNOWN",
      error.message ?? "The request could not be completed.",
      error.detail ?? "",
    );
  }
  return body as T;
}

export const api = {
  get: <T,>(path: string) => request<T>(path),
  post: <T,>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) }),
  postForm: <T,>(path: string, form: FormData) => request<T>(path, { method: "POST", body: form }),
};

export const endpoints = {
  health: "/api/health",
  status: "/api/status",

  login: "/auth/login",
  logout: "/auth/logout",
  whoami: "/auth/whoami",
  directory: "/auth/directory",
  identities: "/auth/identities",
  keys: "/auth/keys",

  commander: "/commander/dashboard",
  posture: "/commander/posture",
  topology: "/commander/topology",
  roles: "/commander/roles",
  classifications: "/commander/classifications",
  anomalyRules: "/commander/anomaly-rules",
  watermarkEngine: "/commander/watermark-engine",
  systemStatus: "/commander/system-status",

  documents: "/documents",
  document: (id: string) => `/documents/${id}`,
  documentGrants: (id: string) => `/documents/${id}/grants`,
  documentLifecycle: (id: string) => `/documents/${id}/lifecycle`,
  documentSuspend: (id: string) => `/documents/${id}/suspend`,
  documentVersions: (id: string) => `/documents/${id}/versions`,
  purgePlaintext: (id: string) => `/documents/${id}/purge-plaintext`,
  classifications_policy: "/documents/classifications",
  lifecycleStates: "/documents/lifecycle",
  currentPolicy: "/documents/policies/current",

  authorise: "/decrypt/authorize",
  decrypt: "/decrypt",

  sessions: "/sessions",
  session: (id: string) => `/sessions/${id}`,
  sessionFile: (id: string) => `/sessions/${id}/document`,
  sessionEvidence: (id: string) => `/sessions/${id}/evidence-chain`,

  recipients: "/recipients",
  recipientSuspend: (id: string) => `/recipients/${id}/suspend`,
  recipientRevoke: (id: string) => `/recipients/${id}/revoke`,
  recipientRevokeKeys: (id: string) => `/recipients/${id}/keys/revoke`,

  devices: "/devices",
  deviceRevoke: (id: string) => `/devices/${id}/revoke`,
  deviceTrust: (id: string) => `/devices/${id}/trust`,

  ledgerStatus: "/ledger/status",
  ledgerVerify: "/ledger/verify",
  ledgerBlocks: "/ledger/blocks",
  ledgerTransactions: "/ledger/transactions",
  ledgerTransaction: (id: string) => `/ledger/transactions/${id}`,
  ledgerSync: "/ledger/sync",
  nodesAdmin: "/ledger/nodes/admin",

  forensicsAnalyze: "/forensics/analyze",
  forensicsExtract: "/forensics/extract",
  forensicsVerify: "/forensics/verify",
  evidenceReport: (id: string) => `/forensics/evidence/${id}/report`,
  evidenceIntegrity: (id: string) => `/forensics/evidence/${id}/report/integrity`,
  evidenceExport: "/evidence/export",

  investigations: "/investigations",
  investigation: (id: string) => `/investigations/${id}`,
  investigationNotes: (id: string) => `/investigations/${id}/notes`,
  investigationClose: (id: string) => `/investigations/${id}/close`,

  securityEvents: "/security-events",
  acknowledgeEvent: (id: string) => `/security-events/${id}/acknowledge`,
  incidents: "/incidents",
  lockdown: "/lockdown",
  unlock: "/unlock",
  approvals: "/approvals",
  approvalApprove: (id: string) => `/approvals/${id}/approve`,
  approvalDeny: (id: string) => `/approvals/${id}/reject`,
  breakGlass: "/approvals/break-glass",
  audit: "/audit",

  aiHealth: "/ai/health",
  aiBriefing: "/ai/briefing",
  aiClusters: "/ai/clusters",
  aiExplainEvent: "/ai/explain-event",

  labScenarios: "/security-lab/scenarios",
  labSimulate: "/security-lab/simulate",
  robustness: "/watermarks/robustness",
};
