export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export interface User { userId: string; orgId: string; role: string; source?: string; mfa?: boolean; mustChangePassword?: boolean }
export interface ManagedUser { userId: string; role: string; disabled: boolean; mfa: boolean; mustChangePassword: boolean; source: string }
export interface Incident { id: string; title: string; severity: Severity; status: string; assignee?: string; labels: string[]; eventIds: string[]; users: string[]; ips: string[]; linkReasons: string[]; firstSeen: string; lastSeen: string; alertIds: string[] }
export interface Ev { id: string; timestamp: string; source: string; type: string; user?: string; ip?: string; resource?: string }
export interface TimelineItem { at: string; kind: string; actor: string; text: string; refs: string[] }
export interface Recommendation { id: string; kind: string; target: string; rationale: string; evidenceIds: string[]; executable: boolean }
export interface Analysis { id: string; provider: string; generatedAt: string; summary: string; hypotheses: { statement: string; confidence: string; evidenceIds: string[] }[]; recommendations: Recommendation[]; gaps: string[] }
export interface Action { id: string; incidentId: string; type: string; target: string; status: string; proposedBy: string; decidedBy?: string; result?: string; mode: string }
export interface Detail { incident: Incident; evidence: Ev[]; timeline: TimelineItem[]; analyses: Analysis[]; actions: Action[] }
export interface Dashboard { events: number; alerts: number; alertsBySeverity: Record<Severity, number>; openIncidents: number; medianTriageMinutes: number | null; falsePositiveRate: number | null; pendingActions: number }

export class ApiError extends Error { constructor(public status: number, public code: string, message: string) { super(message); } }

let token = '';
try { token = sessionStorage.getItem('aegis.token') ?? ''; } catch { /* storage unavailable */ }
export const setToken = (t: string) => { token = t; try { t ? sessionStorage.setItem('aegis.token', t) : sessionStorage.removeItem('aegis.token'); } catch { /* ignore */ } };
export const hasToken = () => !!token;

export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch('/api/v1' + path, {
    method: init.method ?? 'GET',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, json.error ?? 'error', json.message ?? `HTTP ${res.status}`);
  return json as T;
}

export const can = (role: string, perm: 'propose' | 'approve' | 'write' | 'audit' | 'users') =>
  ({ propose: ['analyst', 'approver', 'admin'], approve: ['approver', 'admin'], write: ['analyst', 'approver', 'admin'], audit: ['auditor', 'admin'], users: ['admin'] })[perm].includes(role);
