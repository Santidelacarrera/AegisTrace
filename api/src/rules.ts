import { NormEvent, Severity } from './types.js';

export interface AlertCandidate {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  title: string;
  explanation: string;
  subject: string;
  events: NormEvent[];
}

export const RULE_CONFIG = {
  bruteForce: { threshold: 5, windowMs: 5 * 60_000, successWithinMs: 10 * 60_000 },
  spraying: { threshold: 5, minUsers: 3, windowMs: 5 * 60_000 },
  authz: { threshold: 3, windowMs: 10 * 60_000, highThreshold: 10 },
  adminRoles: ['admin', 'owner', 'root', 'superuser', 'administrator', '*'],
};

const ts = (e: NormEvent) => Date.parse(e.timestamp);
const byTime = (a: NormEvent, b: NormEvent) => ts(a) - ts(b) || a.id.localeCompare(b.id);

/** Split into clusters whose consecutive gap <= windowMs; keep clusters that contain `threshold` events inside one window. */
function bursts(events: NormEvent[], threshold: number, windowMs: number): NormEvent[][] {
  const sorted = [...events].sort(byTime);
  const clusters: NormEvent[][] = [];
  for (const e of sorted) {
    const last = clusters[clusters.length - 1];
    if (last && ts(e) - ts(last[last.length - 1]!) <= windowMs) last.push(e);
    else clusters.push([e]);
  }
  return clusters.filter((c) => {
    for (let i = 0, j = 0; j < c.length; j++) {
      while (ts(c[j]!) - ts(c[i]!) > windowMs) i++;
      if (j - i + 1 >= threshold) return true;
    }
    return false;
  });
}

function groupBy<T>(items: T[], key: (t: T) => string | undefined): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const it of items) {
    const k = key(it);
    if (k === undefined) continue;
    (m.get(k) ?? m.set(k, []).get(k)!).push(it);
  }
  return m;
}

const uniq = <T>(xs: T[]) => [...new Set(xs)];

/**
 * Pure, deterministic detection: same events in -> same candidates out.
 * R001 brute force (per user, or per IP when no user), R002 success after failures,
 * R003 password spraying (per IP, many users), R010 authorization errors, R020 permission change.
 */
export function detect(events: NormEvent[]): AlertCandidate[] {
  const out: AlertCandidate[] = [];
  const failed = events.filter((e) => e.type === 'login_failed');
  const success = events.filter((e) => e.type === 'login_success');
  const { bruteForce: bf, spraying: sp, authz: az } = RULE_CONFIG;

  // R001 + R002
  const subjects = groupBy(failed, (e) => (e.user ? `user:${e.user}` : e.ip ? `ip:${e.ip}` : undefined));
  for (const [subject, evs] of subjects) {
    for (const burst of bursts(evs, bf.threshold, bf.windowMs)) {
      const last = ts(burst[burst.length - 1]!);
      const ips = uniq(burst.map((e) => e.ip).filter(Boolean));
      out.push({
        ruleId: 'R001', ruleName: 'multiple_failed_logins', severity: 'high',
        title: `Repeated failed logins for ${subject}`,
        explanation: `${burst.length} failed logins for ${subject} from ${ips.length || 'unknown'} source IP(s) with at most ${bf.windowMs / 60000} min between consecutive attempts (threshold ${bf.threshold} in ${bf.windowMs / 60000} min).`,
        subject, events: burst,
      });
      const follow = success.filter((s) => {
        const match = subject.startsWith('user:') ? `user:${s.user}` === subject : `ip:${s.ip}` === subject;
        return match && ts(s) >= ts(burst[0]!) && ts(s) - last <= bf.successWithinMs;
      });
      if (follow.length) {
        out.push({
          ruleId: 'R002', ruleName: 'login_success_after_failures', severity: 'critical',
          title: `Successful login after repeated failures for ${subject}`,
          explanation: `A successful login for ${subject} occurred within ${bf.successWithinMs / 60000} min of a burst of ${burst.length} failures; the account may be compromised.`,
          subject, events: [...burst, ...follow].sort(byTime),
        });
      }
    }
  }

  // R003 password spraying
  for (const [ip, evs] of groupBy(failed, (e) => e.ip)) {
    for (const burst of bursts(evs, sp.threshold, sp.windowMs)) {
      const users = uniq(burst.map((e) => e.user).filter(Boolean));
      if (users.length >= sp.minUsers) {
        out.push({
          ruleId: 'R003', ruleName: 'password_spraying', severity: 'high',
          title: `Possible password spraying from ${ip}`,
          explanation: `${burst.length} failed logins from ${ip} against ${users.length} distinct users within a burst (threshold ${sp.minUsers} users).`,
          subject: `ip:${ip}`, events: burst,
        });
      }
    }
  }

  // R010 authorization errors
  for (const [user, evs] of groupBy(events.filter((e) => e.type === 'authz_denied'), (e) => e.user)) {
    for (const burst of bursts(evs, az.threshold, az.windowMs)) {
      const resources = uniq(burst.map((e) => e.resource).filter(Boolean));
      out.push({
        ruleId: 'R010', ruleName: 'repeated_authorization_errors',
        severity: burst.length >= az.highThreshold ? 'high' : 'medium',
        title: `Repeated authorization errors for user:${user}`,
        explanation: `${burst.length} authorization denials for user:${user} across ${resources.length} resource(s) (threshold ${az.threshold} in ${az.windowMs / 60000} min).`,
        subject: `user:${user}`, events: burst,
      });
    }
  }

  // R020 permission change (each event is its own alert)
  for (const e of events.filter((x) => x.type === 'permission_change')) {
    const role = (e.attrs.new_role ?? '').toLowerCase();
    const selfGrant = !!e.attrs.actor && !!e.user && e.attrs.actor.toLowerCase() === e.user;
    const admin = RULE_CONFIG.adminRoles.includes(role);
    const reasons = [admin && `role elevated to "${role}"`, selfGrant && 'actor changed their own permissions'].filter(Boolean);
    out.push({
      ruleId: 'R020', ruleName: 'unexpected_permission_change',
      severity: admin || selfGrant ? 'high' : 'low',
      title: `Permission change for ${e.user ?? 'unknown user'}`,
      explanation: reasons.length ? `Permission change flagged: ${reasons.join('; ')}.` : 'Permission change recorded; no escalation indicators.',
      subject: `event:${e.id}`, events: [e],
    });
  }
  return out;
}
