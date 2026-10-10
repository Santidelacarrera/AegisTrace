import { createHash } from 'node:crypto';
import { detect, AlertCandidate } from './rules.js';
import { OrgData } from './store.js';
import { Alert, Incident, maxSeverity } from './types.js';

export const CORRELATION_WINDOW_MS = 30 * 60_000;
const OPEN = new Set(['open', 'triaging', 'contained']);
const h = (s: string) => createHash('sha256').update(s).digest('hex').slice(0, 16);
const uniq = <T>(xs: T[]) => [...new Set(xs)].sort() as T[];
const clean = <T extends string | undefined>(xs: T[]) => xs.filter((x): x is NonNullable<T> => !!x);

function upsertAlert(org: OrgData, orgId: string, c: AlertCandidate): { alert: Alert; changed: boolean } {
  const ids = c.events.map((e) => e.id);
  let existing: Alert | undefined;
  for (const a of org.alerts.values()) {
    if (a.ruleId === c.ruleId && a.subject === c.subject && a.eventIds.some((i) => ids.includes(i))) { existing = a; break; }
  }
  const fields = {
    severity: c.severity, title: c.title, explanation: c.explanation,
    eventIds: uniq([...(existing?.eventIds ?? []), ...ids]),
    users: uniq(clean(c.events.map((e) => e.user))),
    ips: uniq(clean(c.events.map((e) => e.ip))),
    resources: uniq(clean(c.events.map((e) => e.resource))),
    firstSeen: c.events.map((e) => e.timestamp).sort()[0]!,
    lastSeen: c.events.map((e) => e.timestamp).sort().at(-1)!,
  };
  if (existing) {
    const changed = existing.eventIds.length !== fields.eventIds.length;
    Object.assign(existing, fields);
    return { alert: existing, changed };
  }
  const alert: Alert = {
    id: 'alr_' + h(`${orgId}|${c.ruleId}|${c.subject}|${c.events[0]!.id}`),
    orgId, ruleId: c.ruleId, ruleName: c.ruleName, subject: c.subject, ...fields,
  };
  org.alerts.set(alert.id, alert);
  return { alert, changed: true };
}

function sharedEntities(inc: Incident, a: Alert): string[] {
  return [
    ...a.users.filter((u) => inc.users.includes(u)).map((u) => `user ${u}`),
    ...a.ips.filter((i) => inc.ips.includes(i)).map((i) => `ip ${i}`),
  ];
}

function recompute(org: OrgData, inc: Incident) {
  const alerts = inc.alertIds.map((id) => org.alerts.get(id)!).filter(Boolean);
  inc.eventIds = uniq(alerts.flatMap((a) => a.eventIds));
  inc.users = uniq(alerts.flatMap((a) => a.users));
  inc.ips = uniq(alerts.flatMap((a) => a.ips));
  inc.resources = uniq(alerts.flatMap((a) => a.resources));
  inc.firstSeen = alerts.map((a) => a.firstSeen).sort()[0]!;
  inc.lastSeen = alerts.map((a) => a.lastSeen).sort().at(-1)!;
  inc.severity = alerts.map((a) => a.severity).reduce(maxSeverity);
  const top = [...alerts].sort((a, b) => (a.severity === b.severity ? 0 : maxSeverity(a.severity, b.severity) === a.severity ? -1 : 1))[0]!;
  inc.title = top.title;
}

/** Group alerts into incidents by shared user/IP within a time window, recording why they were linked. */
function correlate(org: OrgData, orgId: string, alert: Alert, now: string) {
  const alertFirst = Date.parse(alert.firstSeen), alertLast = Date.parse(alert.lastSeen);
  const current = alert.incidentId ? org.incidents.get(alert.incidentId) : undefined;
  if (current) { recompute(org, current); current.updatedAt = now; return; }

  const candidates = [...org.incidents.values()]
    .filter((i) => OPEN.has(i.status) && sharedEntities(i, alert).length > 0)
    .filter((i) => alertFirst - Date.parse(i.lastSeen) <= CORRELATION_WINDOW_MS && Date.parse(i.firstSeen) - alertLast <= CORRELATION_WINDOW_MS)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
  const target = candidates[0];
  if (target) {
    const why = `${alert.ruleId} linked to existing incident: shared ${sharedEntities(target, alert).join(', ')} within ${CORRELATION_WINDOW_MS / 60000} min.`;
    target.alertIds.push(alert.id);
    target.linkReasons.push(why);
    target.activity.push({ at: now, kind: 'alert', actor: 'system', text: `Alert ${alert.id} (${alert.ruleId}) correlated. ${why}`, refs: [alert.id, ...alert.eventIds] });
    alert.incidentId = target.id;
    recompute(org, target);
    target.updatedAt = now;
    return;
  }
  const inc: Incident = {
    id: 'inc_' + h(`${orgId}|${alert.id}`), orgId, title: alert.title, severity: alert.severity, status: 'open',
    labels: [], alertIds: [alert.id], eventIds: [], users: [], ips: [], resources: [],
    linkReasons: [`Created from ${alert.ruleId}: ${alert.explanation}`],
    createdAt: now, updatedAt: now, firstSeen: alert.firstSeen, lastSeen: alert.lastSeen,
    activity: [{ at: now, kind: 'alert', actor: 'system', text: `Incident opened from alert ${alert.id} (${alert.ruleId})`, refs: [alert.id, ...alert.eventIds] }],
  };
  org.incidents.set(inc.id, inc);
  alert.incidentId = inc.id;
  recompute(org, inc);
}

/** Re-run deterministic detection over the org's events and correlate new or grown alerts. */
export function runDetection(org: OrgData, orgId: string, now: string): { newAlerts: number; updatedAlerts: number } {
  const events = [...org.events.values()];
  let newAlerts = 0, updatedAlerts = 0;
  const candidates = detect(events).sort((a, b) => a.events[0]!.timestamp.localeCompare(b.events[0]!.timestamp) || a.ruleId.localeCompare(b.ruleId));
  for (const c of candidates) {
    const before = org.alerts.size;
    const { alert, changed } = upsertAlert(org, orgId, c);
    if (org.alerts.size > before) newAlerts++; else if (changed) updatedAlerts++;
    if (changed) correlate(org, orgId, alert, now);
  }
  return { newAlerts, updatedAlerts };
}
