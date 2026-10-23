import type { OrgData } from './store.js';
import { buildChain, ChainVerification, EVIDENCE_FORMAT, EvidenceInput, EvidenceRecord, GENESIS_HASH, verifyAnchor, verifyChain } from './evidence.js';
import { Incident } from './types.js';

export interface EvidenceBundle {
  format: typeof EVIDENCE_FORMAT;
  orgId: string;
  incidentId: string;
  generatedAt: string;
  generatedBy: string;
  /** which record kinds the bundle draws from */
  sources: string[];
  /** references the incident still cites that no longer exist (e.g. removed by retention) */
  missing: string[];
  /** claimed head and entry count; verification recomputes both */
  head: string;
  entries: number;
  records: EvidenceRecord[];
}

const RANK: Record<string, number> = { event: 0, alert: 1, analysis: 2, activity: 3 };

/** Gathers the facts an investigator needs for one incident, from the org's own data only. */
export function collectInputs(org: OrgData, inc: Incident): { inputs: EvidenceInput[]; missing: string[] } {
  const inputs: EvidenceInput[] = [];
  const missing: string[] = [];
  for (const id of inc.eventIds) {
    const e = org.events.get(id);
    if (!e) { missing.push(`event:${id}`); continue; }
    inputs.push({
      at: e.timestamp, kind: 'event', source: e.source, actor: e.source,
      summary: [e.type, e.user && `user=${e.user}`, e.ip && `ip=${e.ip}`, e.resource && `resource=${e.resource}`].filter(Boolean).join(' '),
      refs: [e.id],
      data: { type: e.type, severity: e.severity, user: e.user ?? null, ip: e.ip ?? null, resource: e.resource ?? null, attrs: e.attrs },
    });
  }
  for (const id of inc.alertIds) {
    const a = org.alerts.get(id);
    if (!a) { missing.push(`alert:${id}`); continue; }
    inputs.push({
      at: a.firstSeen, kind: 'alert', source: 'aegistrace.rules', actor: 'system',
      summary: `${a.ruleId} ${a.title}`, refs: [a.id, ...a.eventIds],
      data: { ruleId: a.ruleId, severity: a.severity, subject: a.subject, lastSeen: a.lastSeen, eventIds: a.eventIds },
    });
  }
  for (const an of org.analyses.values()) {
    if (an.incidentId !== inc.id) continue;
    inputs.push({
      at: an.generatedAt, kind: 'analysis', source: 'aegistrace.analysis', actor: an.requestedBy,
      summary: `analysis by ${an.provider}`, refs: [an.id, ...an.summaryEvidenceIds],
      data: { provider: an.provider, summary: an.summary, summaryEvidenceIds: an.summaryEvidenceIds, gaps: an.gaps },
    });
  }
  for (const a of inc.activity) {
    inputs.push({ at: a.at, kind: 'activity', source: 'aegistrace.incident', actor: a.actor, summary: a.text, refs: [...a.refs], data: { activityKind: a.kind } });
  }
  return { inputs, missing };
}

/** Total order that does not depend on locale: time, then kind, then first reference, then summary. */
export function compareInputs(a: EvidenceInput, b: EvidenceInput): number {
  const lt = (x: string, y: string) => (x < y ? -1 : x > y ? 1 : 0);
  return lt(a.at, b.at) || (RANK[a.kind] ?? 9) - (RANK[b.kind] ?? 9) || lt(a.refs[0] ?? '', b.refs[0] ?? '') || lt(a.summary, b.summary);
}

export function buildEvidenceBundle(org: OrgData, inc: Incident, orgId: string, generatedAt: string, generatedBy: string): EvidenceBundle {
  const { inputs, missing } = collectInputs(org, inc);
  inputs.sort(compareInputs);
  const records = buildChain(inputs);
  return {
    format: EVIDENCE_FORMAT, orgId, incidentId: inc.id, generatedAt, generatedBy,
    sources: ['events', 'alerts', 'analyses', 'activity'], missing: missing.sort(),
    head: records.at(-1)?.hash ?? GENESIS_HASH, entries: records.length, records,
  };
}

/**
 * Verifies a bundle with no access to the system: format, every link, and the claimed head/entries.
 * Pass an anchor (head and entries published elsewhere) to also detect truncation and full re-computation.
 */
export function verifyEvidenceBundle(bundle: unknown, anchor?: { head: string; entries: number }): ChainVerification {
  const b = bundle as Partial<EvidenceBundle> | null;
  if (!b || typeof b !== 'object' || b.format !== EVIDENCE_FORMAT || !Array.isArray(b.records)) return { valid: false, entries: 0, head: GENESIS_HASH, reason: 'malformed' };
  const v = verifyChain(b.records);
  if (v.valid && (b.head !== v.head || b.entries !== v.entries)) return { ...v, valid: false, reason: 'claimed_head_mismatch' };
  return verifyAnchor(v, anchor);
}
