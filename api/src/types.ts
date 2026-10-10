export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];
export const sevRank = (s: Severity): number => SEVERITIES.indexOf(s);
export const maxSeverity = (a: Severity, b: Severity): Severity => (sevRank(a) >= sevRank(b) ? a : b);

export type Role = 'viewer' | 'ingestor' | 'analyst' | 'approver' | 'auditor' | 'admin';

export interface Principal {
  userId: string;
  orgId: string;
  role: Role;
}

/** Normalized security event. Free text lives only in `attrs.message` and is untrusted data. */
export interface NormEvent {
  id: string;
  orgId: string;
  timestamp: string; // ISO-8601 UTC
  source: string;
  type: string;
  user?: string;
  ip?: string;
  resource?: string;
  severity: Severity;
  attrs: Record<string, string>;
}

export interface Alert {
  id: string;
  orgId: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  title: string;
  explanation: string;
  subject: string;
  eventIds: string[];
  users: string[];
  ips: string[];
  resources: string[];
  firstSeen: string;
  lastSeen: string;
  incidentId?: string;
}

export const INCIDENT_STATUSES = ['open', 'triaging', 'contained', 'resolved', 'false_positive'] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];

export interface ActivityEntry {
  at: string;
  kind: 'alert' | 'comment' | 'status' | 'assignment' | 'label' | 'analysis' | 'action';
  actor: string;
  text: string;
  refs: string[];
}

export interface Incident {
  id: string;
  orgId: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  assignee?: string;
  labels: string[];
  alertIds: string[];
  eventIds: string[];
  users: string[];
  ips: string[];
  resources: string[];
  linkReasons: string[];
  createdAt: string;
  updatedAt: string;
  firstSeen: string;
  lastSeen: string;
  triagedAt?: string;
  closedAt?: string;
  activity: ActivityEntry[];
}

export interface Hypothesis {
  statement: string;
  confidence: 'low' | 'medium' | 'high';
  evidenceIds: string[];
}

export interface Recommendation {
  id: string;
  incidentId: string;
  orgId: string;
  kind: 'block_ip' | 'disable_user' | 'manual_review';
  target: string;
  rationale: string;
  evidenceIds: string[];
  /** true only when an approvable simulated action exists for it */
  executable: boolean;
}

export interface Analysis {
  id: string;
  incidentId: string;
  orgId: string;
  generatedAt: string;
  provider: string;
  requestedBy: string;
  summary: string;
  summaryEvidenceIds: string[];
  hypotheses: Hypothesis[];
  recommendations: Recommendation[];
  gaps: string[];
}

export type ActionType = 'block_ip' | 'disable_user';
export interface ResponseAction {
  id: string;
  orgId: string;
  incidentId: string;
  recommendationId?: string;
  type: ActionType;
  target: string;
  mode: 'simulated';
  status: 'pending_approval' | 'executed' | 'rejected';
  proposedBy: string;
  decidedBy?: string;
  createdAt: string;
  decidedAt?: string;
  result?: string;
}

export interface AuditEntry {
  seq: number;
  at: string;
  orgId: string;
  actor: string;
  role: string;
  action: string;
  resourceType: string;
  resourceId: string;
  outcome: 'success' | 'denied' | 'error';
  detail?: string;
  prevHash: string;
  hash: string;
}
