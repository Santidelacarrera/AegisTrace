import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { Analysis, Hypothesis, Incident, NormEvent, Alert, Recommendation } from './types.js';

/** Lab scope: simulated actions are only allowed against these targets (RFC 5737 documentation ranges, RFC 1918 10/8, lab-* users). */
export function inLabScope(type: 'block_ip' | 'disable_user', target: string): boolean {
  if (type === 'disable_user') return /^lab[._-][a-z0-9._-]{1,60}$/.test(target);
  if (isIP(target) !== 4) return false;
  return ['192.0.2.', '198.51.100.', '203.0.113.', '10.'].some((p) => target.startsWith(p));
}

export interface AnalysisContext {
  incident: Incident;
  alerts: Alert[];
  events: NormEvent[];
}

/** What a provider (deterministic or LLM) must return. Citations are validated afterwards. */
export interface RawAnalysis {
  summary: string;
  summaryEvidenceIds: string[];
  hypotheses: Hypothesis[];
  recommendations: Omit<Recommendation, 'id' | 'incidentId' | 'orgId' | 'executable'>[];
  gaps: string[];
}

export interface AnalysisProvider {
  name: string;
  analyze(ctx: AnalysisContext): Promise<RawAnalysis>;
}

const uniq = <T>(xs: T[]) => [...new Set(xs)];
const cite = (ids: string[], max = 4) => (ids.length <= max ? ids : ids.slice(0, max)).map((i) => `[${i}]`).join('') + (ids.length > max ? `(+${ids.length - max} more)` : '');
const idsOf = (evs: NormEvent[]) => evs.map((e) => e.id);

/**
 * Deterministic baseline analyst. It only reads structured fields (never the free-text message),
 * so instructions embedded in logs cannot influence its output. An LLM provider can replace it
 * behind the same interface; its output goes through the same citation validation.
 */
export const ruleBasedProvider: AnalysisProvider = {
  name: 'rule-based-v1',
  async analyze({ incident, alerts, events }) {
    const failed = events.filter((e) => e.type === 'login_failed');
    const success = events.filter((e) => e.type === 'login_success');
    const authz = events.filter((e) => e.type === 'authz_denied');
    const perm = events.filter((e) => e.type === 'permission_change');
    const ips = uniq(events.map((e) => e.ip).filter((x): x is string => !!x));
    const users = incident.users;
    const hypotheses: Hypothesis[] = [];
    const recs: RawAnalysis['recommendations'] = [];
    const gaps: string[] = [];
    const has = (r: string) => alerts.some((a) => a.ruleId === r);

    if (has('R001') || has('R003')) {
      const single = uniq(failed.map((e) => e.ip)).length === 1;
      hypotheses.push({
        statement: `Credential guessing against ${users.join(', ') || 'unknown accounts'} from ${ips.join(', ') || 'unknown IPs'} (${failed.length} failed logins).`,
        confidence: failed.length >= 8 || has('R003') ? 'high' : 'medium', evidenceIds: idsOf(failed),
      });
      if (failed.length < 8 && single && !has('R002')) {
        hypotheses.push({ statement: 'Benign alternative: a legitimate user mistyping a password or a misconfigured client retrying with a stale credential.', confidence: 'low', evidenceIds: idsOf(failed) });
      }
      for (const ip of ips) recs.push({ kind: 'block_ip', target: ip, rationale: `Source of ${failed.filter((e) => e.ip === ip).length} failed logins.`, evidenceIds: idsOf(failed.filter((e) => e.ip === ip)) });
    }
    if (has('R002')) {
      hypotheses.push({ statement: `Possible account compromise: a successful login for ${users.join(', ')} followed the failed attempts.`, confidence: 'medium', evidenceIds: idsOf([...failed, ...success]) });
      for (const u of users) recs.push({ kind: 'disable_user', target: u, rationale: 'A successful login followed a burst of failures; containing the account prevents further use while it is reviewed.', evidenceIds: idsOf([...failed.filter((e) => e.user === u), ...success.filter((e) => e.user === u)]) });
      gaps.push('No MFA, device or geolocation data is available to tell whether the successful login was the legitimate user.');
    }
    if (has('R010')) {
      const res = uniq(authz.map((e) => e.resource).filter(Boolean));
      hypotheses.push({ statement: `Probing for access beyond the account's permissions: ${authz.length} authorization denials across ${res.length} resource(s).`, confidence: res.length >= 3 ? 'medium' : 'low', evidenceIds: idsOf(authz) });
      hypotheses.push({ statement: 'Benign alternative: a misconfigured role or a recent deployment changed required permissions.', confidence: 'low', evidenceIds: idsOf(authz) });
      recs.push({ kind: 'manual_review', target: authz[0]?.user ?? 'unknown', rationale: 'Review the account\'s role assignments and the denied resources before taking any containment step.', evidenceIds: idsOf(authz) });
    }
    if (has('R020')) {
      hypotheses.push({ statement: `Privilege change recorded for ${perm.map((e) => e.user ?? 'unknown').join(', ')}: ${perm.map((e) => e.attrs.new_role ?? 'unspecified role').join(', ')}.`, confidence: 'medium', evidenceIds: idsOf(perm) });
      recs.push({ kind: 'manual_review', target: perm[0]?.user ?? 'unknown', rationale: 'Confirm the change against an approved change request.', evidenceIds: idsOf(perm) });
      if (perm.some((e) => !e.attrs.actor)) gaps.push('The actor who performed the permission change is not recorded.');
    }
    if (failed.length && !success.length && !has('R002')) gaps.push('No successful-login events are present, so a compromise cannot be confirmed or ruled out from this data.');
    if (ips.length === 0) gaps.push('Events carry no source IP, so source attribution is not possible.');
    if (ips.length && !has('R020')) gaps.push('No IP reputation or geolocation enrichment is available for the source addresses.');
    if (uniq(events.map((e) => e.source)).length === 1) gaps.push(`All evidence comes from a single source (${events[0]?.source}); it could not be cross-checked.`);

    const parts = [`Incident "${incident.title}" is built from ${alerts.length} alert(s) over ${events.length} event(s) between ${incident.firstSeen} and ${incident.lastSeen}.`];
    if (failed.length) parts.push(`${failed.length} failed login(s) ${cite(idsOf(failed))}.`);
    if (success.length) parts.push(`${success.length} successful login(s) ${cite(idsOf(success))}.`);
    if (authz.length) parts.push(`${authz.length} authorization denial(s) ${cite(idsOf(authz))}.`);
    if (perm.length) parts.push(`${perm.length} permission change(s) ${cite(idsOf(perm))}.`);
    parts.push(`Hypotheses are inferences from these events, not confirmed facts.`);
    return { summary: parts.join(' '), summaryEvidenceIds: idsOf(events), hypotheses, recommendations: dedupe(recs), gaps: uniq(gaps) };
  },
};

function dedupe(recs: RawAnalysis['recommendations']) {
  const seen = new Set<string>();
  return recs.filter((r) => !seen.has(r.kind + r.target) && !!seen.add(r.kind + r.target));
}

export class AnalysisValidationError extends Error {}

/** Every cited ID must be an event that belongs to this incident; hypotheses and recommendations must cite something. */
export function validateAnalysis(raw: RawAnalysis, allowed: Set<string>): void {
  const check = (ids: string[], where: string, required: boolean) => {
    if (required && ids.length === 0) throw new AnalysisValidationError(`${where} cites no evidence`);
    for (const id of ids) if (!allowed.has(id)) throw new AnalysisValidationError(`${where} cites unknown event "${id}"`);
  };
  check(raw.summaryEvidenceIds, 'summary', true);
  raw.hypotheses.forEach((h, i) => check(h.evidenceIds, `hypothesis ${i}`, true));
  raw.recommendations.forEach((r, i) => check(r.evidenceIds, `recommendation ${i}`, true));
  for (const m of raw.summary.matchAll(/\[([^\]\s]+)\]/g)) if (!allowed.has(m[1]!)) throw new AnalysisValidationError(`summary text cites unknown event "${m[1]}"`);
}

export async function buildAnalysis(
  provider: AnalysisProvider, ctx: AnalysisContext, requestedBy: string, now: string,
): Promise<{ analysis: Analysis; recommendations: Recommendation[] }> {
  const raw = await provider.analyze(ctx);
  validateAnalysis(raw, new Set(ctx.events.map((e) => e.id)));
  const base = `${ctx.incident.id}|${ctx.incident.eventIds.join(',')}|${provider.name}`;
  const id = 'ana_' + createHash('sha256').update(base + now).digest('hex').slice(0, 16);
  const recommendations: Recommendation[] = raw.recommendations.map((r) => ({
    ...r, id: 'rec_' + createHash('sha256').update(`${id}|${r.kind}|${r.target}`).digest('hex').slice(0, 16),
    incidentId: ctx.incident.id, orgId: ctx.incident.orgId,
    executable: r.kind !== 'manual_review' && inLabScope(r.kind, r.target),
  }));
  return {
    analysis: {
      id, incidentId: ctx.incident.id, orgId: ctx.incident.orgId, generatedAt: now, provider: provider.name, requestedBy,
      summary: raw.summary, summaryEvidenceIds: raw.summaryEvidenceIds, hypotheses: raw.hypotheses,
      recommendations, gaps: raw.gaps,
    },
    recommendations,
  };
}
