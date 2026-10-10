// HOLDOUT 2: written AFTER the rules were extended (R004, R005, service accounts, role patterns, change approvers) using
// holdout 1 for tuning. Different seed, field names, role names, account names and cadences. Looked at once; rules are not
// tuned against it. Contains cases that should still be missed (slower than R004, below R005's thresholds, success beyond
// R002's window) and benign cases that should still alert.
import { writeFileSync } from 'node:fs';
import { Labels } from '../src/evaluation.js';

let seed = 424242;
const rnd = () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const int = (a: number, b: number) => a + Math.floor(rnd() * (b - a + 1));
const pick = <T>(xs: T[]) => xs[int(0, xs.length - 1)]!;
const events: Record<string, unknown>[] = [];
const labels: Labels = { scenarios: {}, events: {} };
let n = 0, slot = 0;
const T0 = Date.parse('2024-11-02T00:00:00Z');
const users = Array.from({ length: 30 }, (_, i) => `staff.${String.fromCharCode(97 + (i % 26))}${i}`);
const ip = () => pick(['198.51.100.', '203.0.113.', '192.0.2.']) + int(1, 250);
const scenario = (id: string, kind: string, malicious: boolean) => { labels.scenarios[id] = { kind, malicious }; return id; };
const startOf = () => (slot++) * 3 * 3600_000;
const MIN = 60_000;

type Ev = { t: 'fail' | 'ok' | 'deny' | 'perm'; user?: string; ip?: string; res?: string; actor?: string; role?: string };
function emit(scn: string, at: number, e: Ev) {
  const id = `k-${String(++n).padStart(5, '0')}`;
  labels.events[id] = scn;
  const d = new Date(T0 + at);
  if (e.t === 'fail' || e.t === 'ok')
    events.push({ id, date: d.toISOString(), service: 'idp', event: e.t === 'fail' ? 'login.failed' : 'login.succeeded', user_id: e.user, remote_addr: e.ip });
  else if (e.t === 'deny')
    events.push({ event_id: id, time: String(Math.floor(d.getTime() / 1000)), system: 'billing-api', event: 'ACCESS-DENIED', account: e.user, client_ip: e.ip, target: e.res });
  else
    events.push({ id, timestamp: d.toISOString(), source: 'directory', event: 'Role Assigned', user: e.user, actor: e.actor, new_role: e.role });
}

// ---- malicious
for (let i = 0; i < 4; i++) { const s = scenario(`dist-bf-${i}`, 'distributed_brute_force', true), t = startOf(), u = pick(users), pool = [ip(), ip(), ip(), ip()]; for (let k = 0; k < 8; k++) emit(s, t + k * 20_000, { t: 'fail', user: u, ip: pool[k % 4] }); }
for (let i = 0; i < 3; i++) { const s = scenario(`slow-bf-${i}`, 'slow_brute_force_3min', true), t = startOf(), u = pick(users), a = ip(); for (let k = 0; k < 11; k++) emit(s, t + k * 3.5 * MIN, { t: 'fail', user: u, ip: a }); }
for (let i = 0; i < 3; i++) { const s = scenario(`glacial-bf-${i}`, 'glacial_brute_force_9min', true), t = startOf(), u = pick(users), a = ip(); for (let k = 0; k < 9; k++) emit(s, t + k * 9 * MIN, { t: 'fail', user: u, ip: a }); }
for (let i = 0; i < 3; i++) { const s = scenario(`stuff-big-${i}`, 'credential_stuffing', true), t = startOf(); for (let k = 0; k < 18; k++) emit(s, t + k * 10_000, { t: 'fail', user: users[k]!, ip: ip() }); }
for (let i = 0; i < 3; i++) { const s = scenario(`stuff-small-${i}`, 'credential_stuffing_small', true), t = startOf(); for (let k = 0; k < 9; k++) emit(s, t + k * 10_000, { t: 'fail', user: users[k + 10]!, ip: ip() }); }
for (let i = 0; i < 3; i++) { const s = scenario(`spray-${i}`, 'slow_spraying', true), t = startOf(), a = ip(); for (let k = 0; k < 9; k++) emit(s, t + k * 50_000, { t: 'fail', user: users[k % 5]!, ip: a }); }
for (let i = 0; i < 3; i++) { const s = scenario(`takeover-${i}`, 'account_takeover', true), t = startOf(), u = pick(users), a = ip(); for (let k = 0; k < 7; k++) emit(s, t + k * 25_000, { t: 'fail', user: u, ip: a }); emit(s, t + 4 * MIN, { t: 'ok', user: u, ip: a }); }
for (let i = 0; i < 3; i++) { const s = scenario(`takeover-late-${i}`, 'takeover_success_after_15min', true), t = startOf(), u = pick(users), a = ip(); for (let k = 0; k < 6; k++) emit(s, t + k * 25_000, { t: 'fail', user: u, ip: a }); emit(s, t + 15 * MIN, { t: 'ok', user: u, ip: a }); }
for (let i = 0; i < 3; i++) { const s = scenario(`enum-${i}`, 'authz_enumeration', true), t = startOf(), u = pick(users), a = ip(); for (let k = 0; k < 12; k++) emit(s, t + k * 40_000, { t: 'deny', user: u, ip: a, res: `/invoices/${5000 + k}` }); }
for (const [i, role] of ['org_super_admin', 'devops-lead', 'billing_manager', 'break-glass'].entries()) { const s = scenario(`priv-${i}`, `privilege_escalation_${role}`, true), t = startOf(); emit(s, t, { t: 'perm', user: pick(users), actor: 'staff.intern', role }); }

// ---- benign
for (const svc of ['svc-batch', 'ci-runner', 'svc-reports', 'etl-bot']) for (let i = 0; i < 2; i++) { const s = scenario(`${svc}-${i}`, 'service_account_retries', false), t = startOf(); for (let k = 0; k < 9; k++) emit(s, t + k * 15_000, { t: 'fail', user: svc, ip: '10.0.0.' + int(2, 9) }); }
for (let i = 0; i < 4; i++) { const s = scenario(`lockout-reset-${i}`, 'forgotten_password_reset', false), t = startOf(), u = pick(users), a = ip(); for (let k = 0; k < 6; k++) emit(s, t + k * 30_000, { t: 'fail', user: u, ip: a }); emit(s, t + 20 * MIN, { t: 'ok', user: u, ip: a }); }
for (let i = 0; i < 4; i++) { const s = scenario(`deploy-wave-${i}`, 'deployment_permission_wave', false), t = startOf(); for (let u = 0; u < 3; u++) for (let k = 0; k < 3; k++) emit(s, t + (u * 3 + k) * 8_000, { t: 'deny', user: users[u + 20]!, ip: ip(), res: '/reports/new' }); }
for (let i = 0; i < 8; i++) { const s = scenario(`typo-${i}`, 'typo', false), t = startOf(), u = pick(users), a = ip(); for (let k = 0; k < int(1, 3); k++) emit(s, t + k * 20_000, { t: 'fail', user: u, ip: a }); emit(s, t + 90_000, { t: 'ok', user: u, ip: a }); }
for (let i = 0; i < 5; i++) { const s = scenario(`approved-promo-${i}`, 'approved_admin_promotion', false), t = startOf(); emit(s, t, { t: 'perm', user: pick(users), actor: 'staff.vp-eng', role: pick(['admin', 'org_admin']) }); }
for (let i = 0; i < 6; i++) { const s = scenario(`member-${i}`, 'routine_role_change', false), t = startOf(); emit(s, t, { t: 'perm', user: pick(users), actor: 'staff.hr', role: pick(['member', 'viewer', 'reader']) }); }
for (let i = 0; i < 4; i++) { const s = scenario(`custom-ok-${i}`, 'benign_custom_role', false), t = startOf(); emit(s, t, { t: 'perm', user: pick(users), actor: 'staff.hr', role: pick(['marketing-editor', 'support-tier1']) }); }
for (let i = 0; i < 30; i++) { const s = scenario(`ok-${i}`, 'normal_login', false), t = startOf(); emit(s, t, { t: 'ok', user: pick(users), ip: ip() }); }

writeFileSync(new URL('../../data/synthetic/holdout2-events.json', import.meta.url), JSON.stringify(events, null, 1) + '\n');
writeFileSync(new URL('../../data/synthetic/holdout2-labels.json', import.meta.url), JSON.stringify(labels, null, 1) + '\n');
console.log(`wrote ${events.length} holdout2 events, ${Object.keys(labels.scenarios).length} scenarios`);
