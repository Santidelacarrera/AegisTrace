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
  slow: { threshold: 8, windowMs: 60 * 60_000 },
  stuffing: { minFailures: 15, minUsers: 10, windowMs: 5 * 60_000 },
  /** Roles whose name suggests broad privilege; anything matching is treated as privileged. */
  privilegedRole: /admin|owner|root|super|full[-_ ]?access|power|manage|write[-_ ]?all|^\*$/i,
  /** Roles known to be low privilege. A role in neither list is "unknown" and gets reviewed (medium). */
  lowRole: /^(viewer|reader|read[-_ ]?only|guest|member|user)$/i,
};

/**
 * Organisation knowledge the rules cannot infer from events alone. Everything here is operator-provided
 * configuration (AEGIS_SERVICE_ACCOUNTS, AEGIS_CHANGE_APPROVERS): exact names or `prefix*` / `*suffix` / `*contains*` patterns.
 */
export interface RuleContext { serviceAccounts: string[]; changeApprovers: string[] }
export const EMPTY_CONTEXT: RuleContext = { serviceAccounts: [], changeApprovers: [] };

export function matchesAny(name: string | undefined, patterns: string[]): boolean {
  if (!name) return false;
  const n = name.toLowerCase();
  return patterns.some((raw) => {
    const p = raw.toLowerCase();
    const starts = p.startsWith('*'), ends = p.endsWith('*');
    const core = p.replace(/^\*|\*$/g, '');
    if (starts && ends) return n.includes(core);
    if (ends) return n.startsWith(core);
    if (starts) return n.endsWith(core);
    return n === p;
  });
}

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
export function detect(events: NormEvent[], ctx: RuleContext = EMPTY_CONTEXT): AlertCandidate[] {
  const out: AlertCandidate[] = [];
  const isService = (u?: string) => matchesAny(u, ctx.serviceAccounts);
  const failed = events.filter((e) => e.type === 'login_failed');
  const success = events.filter((e) => e.type === 'login_success');
  const { bruteForce: bf, spraying: sp, authz: az } = RULE_CONFIG;

  const r001Sets: Map<string, Set<string>[]> = new Map();
  // R001 + R002
  const subjects = groupBy(failed, (e) => (e.user ? `user:${e.user}` : e.ip ? `ip:${e.ip}` : undefined));
  for (const [subject, evs] of subjects) {
    for (const burst of bursts(evs, bf.threshold, bf.windowMs)) {
      const last = ts(burst[burst.length - 1]!);
      const ips = uniq(burst.map((e) => e.ip).filter(Boolean));
      const svc = subject.startsWith('user:') && isService(subject.slice(5));
      (r001Sets.get(subject) ?? r001Sets.set(subject, []).get(subject)!).push(new Set(burst.map((e) => e.id)));
      out.push({
        ruleId: 'R001', ruleName: 'multiple_failed_logins', severity: svc ? 'low' : 'high',
        title: `Repeated failed logins for ${subject}`,
        explanation: `${burst.length} failed logins for ${subject} from ${ips.length || 'unknown'} source IP(s) with at most ${bf.windowMs / 60000} min between consecutive attempts (threshold ${bf.threshold} in ${bf.windowMs / 60000} min).${svc ? ' Configured service account: retries are expected, severity lowered.' : ''}`,
        subject, events: burst,
      });
      const follow = success.filter((s) => {
        const match = subject.startsWith('user:') ? `user:${s.user}` === subject : `ip:${s.ip}` === subject;
        return match && ts(s) >= ts(burst[0]!) && ts(s) - last <= bf.successWithinMs;
      });
      if (follow.length && !svc) {
        out.push({
          ruleId: 'R002', ruleName: 'login_success_after_failures', severity: 'critical',
          title: `Successful login after repeated failures for ${subject}`,
          explanation: `A successful login for ${subject} occurred within ${bf.successWithinMs / 60000} min of a burst of ${burst.length} failures; the account may be compromised.`,
          subject, events: [...burst, ...follow].sort(byTime),
        });
      }
    }
  }

  // R004 low-and-slow brute force: many failures per user over an hour, even when no 5-minute burst exists
  for (const [subject, evs] of groupBy(failed, (e) => (e.user ? `user:${e.user}` : undefined))) {
    if (isService(subject.slice(5))) continue;
    for (const burst of bursts(evs, RULE_CONFIG.slow.threshold, RULE_CONFIG.slow.windowMs)) {
      const covered = (r001Sets.get(subject) ?? []).some((set) => burst.filter((e) => set.has(e.id)).length >= burst.length / 2);
      if (covered) continue;                                  // R001 already reports this activity
      out.push({
        ruleId: 'R004', ruleName: 'low_and_slow_failed_logins', severity: 'medium',
        title: `Slow, sustained failed logins for ${subject}`,
        explanation: `${burst.length} failed logins for ${subject} spread over ${Math.round((ts(burst[burst.length - 1]!) - ts(burst[0]!)) / 60000)} min without a short burst (threshold ${RULE_CONFIG.slow.threshold} in ${RULE_CONFIG.slow.windowMs / 60000} min); possible throttle-evading guessing.`,
        subject, events: burst,
      });
    }
  }

  // R005 credential stuffing: failures across many accounts in a short window regardless of source IP
  {
    const { minFailures, minUsers, windowMs } = RULE_CONFIG.stuffing;
    const human = failed.filter((e) => e.user && !isService(e.user));
    for (const burst of bursts(human, minFailures, windowMs)) {
      const users = uniq(burst.map((e) => e.user).filter(Boolean));
      if (users.length >= minUsers) {
        out.push({
          ruleId: 'R005', ruleName: 'credential_stuffing', severity: 'high',
          title: `Possible credential stuffing across ${users.length} accounts`,
          explanation: `${burst.length} failed logins against ${users.length} distinct accounts from ${uniq(burst.map((e) => e.ip).filter(Boolean)).length || 'unknown'} source IP(s) in a burst (threshold ${minFailures} failures over ${minUsers} accounts).`,
          subject: 'global:credential_stuffing', events: burst,
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
      const svc = isService(user);
      out.push({
        ruleId: 'R010', ruleName: 'repeated_authorization_errors',
        severity: svc ? 'low' : burst.length >= az.highThreshold ? 'high' : 'medium',
        title: `Repeated authorization errors for user:${user}`,
        explanation: `${burst.length} authorization denials for user:${user} across ${resources.length} resource(s) (threshold ${az.threshold} in ${az.windowMs / 60000} min).`,
        subject: `user:${user}`, events: burst,
      });
    }
  }

  // R020 permission change (each event is its own alert)
  for (const e of events.filter((x) => x.type === 'permission_change')) {
    const role = (e.attrs.new_role ?? '').trim();
    const selfGrant = !!e.attrs.actor && !!e.user && e.attrs.actor.toLowerCase() === e.user;
    const privileged = !!role && RULE_CONFIG.privilegedRole.test(role);
    const unknown = !!role && !privileged && !RULE_CONFIG.lowRole.test(role);
    const approved = !!e.attrs.actor && !selfGrant && matchesAny(e.attrs.actor, ctx.changeApprovers);
    const reasons = [privileged && `role "${role}" looks privileged`, unknown && `role "${role}" is not a known low-privilege role`, selfGrant && 'actor changed their own permissions', !role && 'no role recorded'].filter(Boolean);
    const severity: Severity = selfGrant ? 'high' : approved ? 'low' : privileged ? 'high' : unknown || !role ? 'medium' : 'low';
    out.push({
      ruleId: 'R020', ruleName: 'unexpected_permission_change', severity,
      title: `Permission change for ${e.user ?? 'unknown user'}`,
      explanation: (reasons.length ? `Permission change flagged: ${reasons.join('; ')}.` : 'Permission change recorded; no escalation indicators.') + (approved ? ` Performed by a configured change approver (${e.attrs.actor}); severity lowered.` : ''),
      subject: `event:${e.id}`, events: [e],
    });
  }
  return out;
}
