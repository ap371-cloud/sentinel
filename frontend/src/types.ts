/* ------------------------------------------------------------------ health */

export type Health = {
  status: string;
  service: string;
  version: string;
  post_quantum: { signing: string; kem: string; backend: string; production_grade_backend: boolean };
  disclaimer: string;
};

/* ----------------------------------------------------------------- identity */

export type Identity = {
  recipient_id: string;
  display_name: string;
  role: string;
  unit: string;
  clearance: number;
  clearance_label: string;
  status: string;
  email: string;
  created_at: string;
  last_login_at: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
};

export type RecipientsResponse = {
  identities: Identity[];
  counts: { total: number; active: number; inactive: number };
};

export type DeviceRow = {
  device_id: string;
  recipient_id: string;
  device_name: string;
  status: string;
  trust_state: string;
  trust_assessed_at: string | null;
  trust_note: string | null;
  registered_at: string;
  last_seen_at: string | null;
  attestation_note: string | null;
};

export type DevicesResponse = {
  devices: DeviceRow[];
  trust_states: string[];
  limitation: string;
};

export type WhoAmI = {
  identity: Identity;
  permissions: string[];
  devices: {
    device_id: string;
    device_name: string;
    fingerprint: string;
    status: string;
    registered_at: string;
    last_seen_at: string | null;
    revoked_at: string | null;
    attestation_note: string | null;
  }[];
  clearance_label: string;
};

export type LoginResponse = {
  token: string;
  token_type: string;
  expires_in_seconds: number;
  identity: Identity;
  devices: unknown[];
  plain_explanation: string;
};

/* ---------------------------------------------------------------- documents */

export type DocumentRow = {
  document_id: string;
  uuid: string;
  title: string;
  classification: string;
  classification_label: string;
  owner_id: string;
  owning_unit: string;
  current_version: number;
  status: string;
  lifecycle_state: string;
  current_version_sha256: string;
  page_count: number;
  size_bytes: number;
  authorized_recipients: string[];
  created_at: string;
  access_expiry: string | null;
  sessions_used: number;
  maximum_sessions: number;
};

export type DocumentPolicy = {
  document_id: string;
  classification: string;
  permitted_roles: string[];
  permitted_units: string[];
  need_to_know_units: string[];
  download_allowed: boolean;
  print_allowed: boolean;
  export_allowed: boolean;
  offline_allowed: boolean;
  watermark_required: boolean;
  second_approval_required: boolean;
  access_expiry: string | null;
  maximum_sessions: number;
  mission_reference: string | null;
  policy_version: string;
};

export type DocumentVersionRow = {
  version_id: string;
  version_number: number;
  label: string;
  content_sha256: string;
  size_bytes: number;
  page_count: number;
  classification: string;
  is_current: boolean;
  created_at: string;
  created_by: string;
  encrypted: boolean;
  key_wrap_algorithm: string;
  recipient_key_wraps: number;
};

export type AccessRecord = {
  session_id: string;
  recipient_id: string;
  device_id: string;
  version_number: number;
  issued_at: string;
  completed_at: string | null;
  status: string;
  break_glass: boolean;
};

export type DocumentDetail = DocumentRow & {
  policy: DocumentPolicy;
  policy_note: string;
  mission_reference: string | null;
  versions: DocumentVersionRow[];
  lifecycle_history: { from: string; to: string; at: string; reason: string }[];
  access_history: AccessRecord[];
  crypto: {
    content_cipher: string;
    content_note: string;
    key_wrap: string;
    key_wrap_note: string;
  };
};

export type AuthCheck = {
  check: string;
  passed: boolean;
  reason_code: string;
  plain_explanation: string;
};

export type DecryptionResult = {
  session_id: string;
  document_id: string;
  version_id: string;
  version_number: number;
  classification: string;
  recipient_id: string;
  device_id: string;
  watermark_id: string;
  watermark_tag: string;
  watermark_quality: { psnr_db: number; ssim: number; carriers_per_bit: number };
  output_path: string;
  event_id: string;
  event_hash: string;
  signature_algorithm: string;
  ledger: { status: string; committed: boolean; block_id?: string; quorum_votes?: string[] };
  break_glass: boolean;
  authorization_checks: AuthCheck[];
  decrypted_at: string;
  viewer_note: string;
};

/* ----------------------------------------------------------------- sessions */

export type SessionRow = {
  session_id: string;
  document_id: string;
  version_id: string;
  version_number: number;
  recipient_id: string;
  device_id: string;
  issued_at: string;
  completed_at: string | null;
  status: string;
  request_id: string;
  break_glass: boolean;
  break_glass_reason: string | null;
  policy_version: string;
  watermark_version: string;
  watermark_id: string | null;
  watermark_tag: string | null;
  ledger_tx_id?: string | null;
  ledger_committed?: boolean;
};

export type SessionDetail = SessionRow & {
  nonce_consumed: boolean;
  single_use_enforced: boolean;
  authorization_checks: AuthCheck[];
  watermark_quality: { psnr_db: number; ssim: number; carriers_per_bit: number } | null;
  signature: {
    event_id: string;
    event_hash: string;
    algorithm: string;
    signing_key_id: string;
    signature: string;
    prev_event_hash: string;
  } | null;
  ledger_tx_id: string | null;
  ledger_committed: boolean;
};

/* -------------------------------------------------------------- dashboard */

export type Kpi = {
  documents_protected: number;
  active_recipients: number;
  revoked_recipients: number;
  suspended_recipients: number;
  active_sessions: number;
  registered_devices: number;
  revoked_devices: number;
  security_events_open: number;
  critical_incidents: number;
  high_incidents: number;
  watermarks_issued: number;
  open_investigations: number;
  verified_evidence: number;
  pending_approvals: number;
};

export type Posture = {
  score: number;
  rating: string;
  factors: { factor: string; value: number; detail: string }[];
  basis: string;
  disclaimer: string;
};

export type LedgerNode = {
  node_id: string;
  status: string;
  block_height: number;
  latest_block_hash: string;
  previous_block_hash: string;
  latest_merkle_root: string;
  state_root: string;
  pending_sync_count: number;
  public_key?: string;
};

export type SecurityEvent = {
  security_event_id: string;
  category: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  title: string;
  plain_explanation: string;
  command_brief: {
    what_happened: string;
    why_it_is_important: string;
    what_was_affected: string;
    recommended_action: string;
  };
  actor_id: string | null;
  subject_id: string | null;
  document_id: string | null;
  session_id: string | null;
  status: string;
  detail: Record<string, unknown>;
  detected_at: string;
  acknowledged_by: string | null;
};

export type SecurityEventsResponse = {
  events: SecurityEvent[];
  counts_by_severity: Record<string, number>;
  open_count: number;
  severity_levels: string[];
};

export type Dashboard = {
  system_security_status: string;
  kpis: Kpi;
  security_posture: Posture;
  ledger_health: { headline: string; agreement: string; nodes: LedgerNode[]; quorum_size: number };
  live_security_events: SecurityEvent[];
  recent_decryptions: SessionRow[];
  recent_investigations: {
    case_id: string;
    title: string;
    status: string;
    final_verification_status: string | null;
    created_at: string;
  }[];
  watermark_engine: Record<string, unknown>;
  air_gap: Record<string, unknown>;
  post_quantum: Record<string, unknown>;
  key_vault: Record<string, unknown>;
  topology: { component: string; status: string; purpose: string }[];
  attribution_statement: string;
};

/* ------------------------------------------------------------------ ledger */

export type LedgerStatus = {
  nodes: LedgerNode[];
  node_count: number;
  reachable_nodes: number;
  quorum_size: number;
  quorum_reachable: boolean;
  consensus: string;
  pending_sync_total: number;
  offline_mode: boolean;
  plain_explanation: string;
};

export type LedgerVerification = {
  headline: string;
  nodes: {
    node_id: string;
    status: string;
    block_height: number;
    blocks_checked: number;
    transactions_checked: number;
    first_failing_height: number | null;
    failures: { height: number; check: string; detail: string }[];
    state_root: string;
    plain_explanation: string;
  }[];
  agreement: {
    status: string;
    agreed_height: number;
    state_root: string;
    quorum_members: string[];
    divergent: string[];
    plain_explanation: string;
  };
  quorum_size: number;
  node_count: number;
  verified_at: string;
};

export type Block = {
  block_id: string;
  height: number;
  previous_hash: string;
  merkle_root: string;
  block_hash: string;
  timestamp: string;
  proposer_id: string;
  certificate: string;
  signature_algorithm: string;
  block_signature: string;
  signing_key_id: string;
  transaction_count: number;
  tx_ids: string[];
  state_root: string;
  is_genesis: boolean;
  note: string;
};

export type LedgerTx = {
  tx_id: string;
  event_id: string;
  event_hash: string;
  event_type: string;
  recipient_id: string;
  document_id: string;
  version_id: string;
  document_hash: string;
  watermark_tag: string;
  session_id: string;
  payload: Record<string, unknown>;
  recipient_signature: string;
  signature_algorithm: string;
  signing_key_id: string;
  tx_hash: string;
  committed_block_id: string | null;
  merkle_index: number | null;
  committed_at: string;
  submitted_by_node: string;
};

/* -------------------------------------------------------------- forensics */

export type ChainLink = {
  link: string;
  status: "PASS" | "PARTIAL" | "FAIL" | "UNKNOWN";
  detail: string;
  evidence?: Record<string, unknown>;
};

export type WatermarkFinding = {
  status: string;
  recovered_tag: string | null;
  confidence: number;
  carrier_to_noise_ratio: number;
  estimated_bit_errors: number;
  plain_explanation: string;
  matched_session_id: string | null;
};

export type ForensicAnalysis = {
  evidence_id: string;
  case_id: string;
  outcome: string;
  chain_summary: { links_total: number; links_passed: number; links_partial: number; links_failed: number };
  evidence_chain: ChainLink[];
  matched_recipient_id: string | null;
  matched_session_id: string | null;
  matched_document_id: string | null;
  matched_version_id: string | null;
  content_sha256: string;
  limitations: string[];
  outcome_explanation: string;
  watermark: WatermarkFinding;
};

export type EvidenceRow = {
  evidence_id: string;
  outcome?: string;
  created_at?: string;
};

export type InvestigationRow = {
  case_id: string;
  title: string;
  investigator_id: string;
  status: string;
  summary: string;
  notes: { note: string; author_id: string; at: string }[];
  final_verification_status: string | null;
  attributed_recipient_id: string | null;
  attributed_session_id: string | null;
  report_path: string | null;
  report_sha256: string | null;
  report_integrity: Record<string, unknown> | null;
  created_at: string;
  closed_at: string | null;
  evidence: EvidenceRow[];
  history_preserved: boolean;
  deletion_note: string;
  evidence_count?: number;
};

export type EvidenceReport = {
  evidence_id: string;
  case_id?: string;
  outcome: string;
  generated_at: string;
  report_sha256: string;
  confidence: number;
  content_sha256: string;
  watermark: WatermarkFinding;
  evidence_chain: ChainLink[];
  limitations: string[];
  plain_explanation: string;
};

export type RobustnessReport = {
  transformations_tested: number;
  transformations_recovered: number;
  results: {
    transformation: string;
    recovered: boolean;
    carrier_to_noise_ratio: number;
    estimated_bit_errors: number;
  }[];
  tested_at: string;
  known_limitations: string[];
};

/* ---------------------------------------------------------- security ops */

export type IncidentRow = {
  incident_id: string;
  title: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: string;
  category: string;
  what_happened: string;
  why_it_matters: string;
  affected_resources: string[];
  recommended_response: string[];
  timeline: { at: string; text: string }[];
  linked_event_id: string | null;
  linked_case_id: string | null;
  owner_id: string | null;
  opened_at: string;
  closed_at: string | null;
};

export type Approval = {
  approval_id: string;
  action: string;
  subject_id: string | null;
  justification: string;
  requested_by: string;
  required_approvals: number;
  approvals_recorded: string[];
  approvals_counted: number;
  approvals_remaining: number;
  rejections: string[];
  status: string;
  created_at: string;
  expires_at: string;
  consumed: boolean;
  sufficient: boolean;
  plain_explanation: string;
};

export type ApprovalsResponse = {
  approvals: Approval[];
  high_risk_actions: string[];
  approver_roles: string[];
  plain_explanation: string;
};

export type AuditRow = {
  audit_id: string;
  actor_id: string;
  actor_role: string;
  action: string;
  target_type: string;
  target_id: string | null;
  outcome: string;
  detail: string;
  occurred_at: string;
  record_hash: string;
  prev_record_hash: string;
};

export type AuditResponse = {
  chain: {
    chain_length: number;
    head: string;
    status: string;
    first_broken_record: string | null;
    plain_explanation: string;
  };
  privileged_actions: AuditRow[];
  categories: string[];
  note: string;
};

export type LockdownState = {
  system_status: string;
  lockdown_active: boolean;
  lockdown_reason: string | null;
  lockdown_activated_by: string | null;
  lockdown_activated_at: string | null;
  air_gap_violation: boolean;
  plain_explanation: string;
};

export type LabScenario = {
  key: string;
  title: string;
  what_it_does: string;
  expected_detection: string;
};

export type LabScenariosResponse = {
  environment: string;
  scenarios: LabScenario[];
  disclaimer: string;
};

export type LabOutcome = {
  simulation: string;
  label: string;
  detected: boolean;
  detected_as: string;
  outcome: string;
  detail: string;
  executed_at: string;
};

/* ---------------------------------------------------------------------- ai */

export type AiHealth = {
  available: boolean;
  endpoint: string;
  models: string[];
  configured_model: string;
  model_present: boolean;
  status: string;
  reason: string;
  role: string;
  impact: string;
};

export type AiBriefingResponse = {
  briefing: {
    label: string;
    available: boolean;
    summary: string | null;
    fallback: string;
    requested: string;
    at: string;
    health: AiHealth;
  };
  deterministic_state: {
    system_security_status: string;
    posture: number;
    ledger_integrity: string;
  };
};

export type AiClustersResponse = {
  label: string;
  available: boolean;
  clusters: { category: string; count: number; events: SecurityEvent[] }[];
  note: string;
};
