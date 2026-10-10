import { OrgData } from './store.js';

export interface RetentionPolicy { eventDays: number; incidentDays: number }
export interface RetentionResult { events: number; alerts: number; incidents: number; analyses: number; actions: number; dryRun: boolean; cutoff: { events: string; incidents: string } }

const DAY = 86_400_000;

/**
 * Deletes old data in dependency order and never removes evidence still in use:
 *  - closed incidents (resolved / false_positive) older than incidentDays, with their alerts, analyses, recommendations and actions;
 *  - events older than eventDays that no remaining incident references.
 * Open incidents and everything they cite are kept regardless of age. The audit log is never purged here:
 * removing a prefix would break the hash chain, so audit retention is a separate, deliberate operation.
 */
export function applyRetention(org: OrgData, policy: RetentionPolicy, nowMs: number, dryRun = false): RetentionResult {
  const incCut = nowMs - policy.incidentDays * DAY, evCut = nowMs - policy.eventDays * DAY;
  const res: RetentionResult = { events: 0, alerts: 0, incidents: 0, analyses: 0, actions: 0, dryRun, cutoff: { events: new Date(evCut).toISOString(), incidents: new Date(incCut).toISOString() } };

  const dropInc = [...org.incidents.values()].filter((i) => (i.status === 'resolved' || i.status === 'false_positive') && Date.parse(i.closedAt ?? i.updatedAt) < incCut);
  const dropIds = new Set(dropInc.map((i) => i.id));
  const dropAlerts = [...org.alerts.values()].filter((a) => a.incidentId && dropIds.has(a.incidentId));
  const rows = (m: Map<string, { incidentId: string }>) => [...m].filter(([, v]) => dropIds.has(v.incidentId)).map(([k]) => k);
  const anaIds = rows(org.analyses as never), recIds = rows(org.recommendations as never), actIds = rows(org.actions as never);

  // Evidence still referenced after the incidents above are gone
  const keep = new Set<string>();
  for (const i of org.incidents.values()) if (!dropIds.has(i.id)) i.eventIds.forEach((e) => keep.add(e));
  for (const a of org.alerts.values()) if (!dropAlerts.includes(a)) a.eventIds.forEach((e) => keep.add(e));
  const dropEvents = [...org.events.values()].filter((e) => Date.parse(e.timestamp) < evCut && !keep.has(e.id)).map((e) => e.id);

  Object.assign(res, { events: dropEvents.length, alerts: dropAlerts.length, incidents: dropInc.length, analyses: anaIds.length, actions: actIds.length });
  if (dryRun) return res;
  dropAlerts.forEach((a) => org.alerts.delete(a.id));
  dropInc.forEach((i) => org.incidents.delete(i.id));
  anaIds.forEach((k) => org.analyses.delete(k)); recIds.forEach((k) => org.recommendations.delete(k)); actIds.forEach((k) => org.actions.delete(k));
  dropEvents.forEach((id) => org.events.delete(id));
  org.pendingEventDeletes.push(...dropEvents);
  return res;
}
