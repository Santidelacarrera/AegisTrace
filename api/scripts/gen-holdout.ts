// HOLDOUT dataset: different seed, different source formats, and attack/benign behaviours that were NOT used to
// choose rule thresholds. It is meant to expose weaknesses, so it contains cases the rules are expected to miss
// (slow attacks, credential stuffing) and benign cases they are expected to flag (retrying service accounts,
// post-vacation typos, deployment-induced denials). Do not tune rules against it; report whatever it gives.
import { writeFileSync } from 'node:fs';
import { Labels } from '../src/evaluation.js';

let seed = 987654321;
const rnd = () => { seed |= 0; seed = (seed + 0x9e3779b9) | 0; let t = Math.imul(seed ^ (seed >>> 16), 0x85ebca6b); t = Math.imul(t ^ (t >>> 13), 0xc2b2ae35); return ((t ^ (t >>> 16)) >>> 0) / 4294967296; };
const int = (a: number, b: number) => a + Math.floor(rnd() * (b - a + 1));
const pick = <T>(xs: T[]) => xs[int(0, xs.length - 1)]!;
const events: Record<string, unknown>[] = [];
const labels: Labels = { scenarios: {}, events: {} };
let n = 0, slot = 0;
const T0 = Date.parse('2024-09-14T00:00:00Z');
const users = Array.from({ length: 25 }, (_, i) => `lab.user${String(i).padStart(2, '0')}`);
const ips = () => pick(['198.51.100.', '203.0.113.', '192.0.2.']) + int(1, 250);
const scenario = (id: string, kind: string, malicious: boolean) => { labels.scenarios[id] = { kind, malicious }; return id; };
const startOf = () => (slot++) * 3 * 3600_000;

// Each source uses its own field names and time format, like real heterogeneous exports.
type Ev = { type: 'fail' | 'ok' | 'deny' | 'perm'; user?: string; ip?: string; resource?: string; actor?: string; role?: string };
function emit(scn: string, at: number, e: Ev) {
  const id = `h-${String(++n).padStart(5, '0')}`;
  labels.events[id] = scn;
  const iso = new Date(T0 + at).toISOString();
  if (e.type === 'fail' || e.type === 'ok')
    events.push({ event_id: id, '@timestamp': iso, service: 'sso-gateway', event: e.type === 'fail' ? 'AUTHENTICATION_FAILED' : 'AUTH_SUCCESS', account: e.user, client_ip: e.ip });
  else if (e.type === 'deny')
    events.push({ id, ts: Math.floor((T0 + at) / 1000), system: 'orders-api', action: 'HTTP_403', username: e.user, src_ip: e.ip, path: e.resource });
  else
    events.push({ id, time: iso.replace('Z', '+00:00'), source: 'iam', type: 'IAM_POLICY_CHANGE', user: e.user, performed_by: e.actor, role: e.role });
}

// --- malicious
for (let i = 0; i < 4; i++) { const s = scenario(`distributed-bf-${i}`, 'distributed_brute_force', true), t = startOf(), u = pick(users); for (let k = 0; k < 9; k++) emit(s, t + k * 25_000, { type: 'fail', user: u, ip: ips() }); }
for (let i = 0; i < 3; i++) { const s = scenario(`slow-bf-${i}`, 'low_and_slow_brute_force', true), t = startOf(), u = pick(users), ip = ips(); for (let k = 0; k < 12; k++) emit(s, t + k * 110_000, { type: 'fail', user: u, ip }); }
for (let i = 0; i < 3; i++) { const s = scenario(`stuffing-${i}`, 'credential_stuffing', true), t = startOf(); for (let k = 0; k < 20; k++) emit(s, t + k * 8_000, { type: 'fail', user: users[k]!, ip: ips() }); }
for (let i = 0; i < 3; i++) { const s = scenario(`spray-${i}`, 'password_spraying', true), t = startOf(), ip = ips(); for (let k = 0; k < 12; k++) emit(s, t + k * 20_000, { type: 'fail', user: users[k % 6]!, ip }); }
for (let i = 0; i < 3; i++) { const s = scenario(`takeover-${i}`, 'account_takeover', true), t = startOf(), u = pick(users), ip = ips(); for (let k = 0; k < 6; k++) emit(s, t + k * 30_000, { type: 'fail', user: u, ip }); emit(s, t + 6 * 30_000 + 90_000, { type: 'ok', user: u, ip }); }
for (let i = 0; i < 3; i++) { const s = scenario(`idor-${i}`, 'authz_probing', true), t = startOf(), u = pick(users), ip = ips(); for (let k = 0; k < 15; k++) emit(s, t + k * 12_000, { type: 'deny', user: u, ip, resource: `/orders/${1000 + k}` }); }
for (let i = 0; i < 2; i++) { const s = scenario(`priv-owner-${i}`, 'privilege_escalation', true), t = startOf(); emit(s, t, { type: 'perm', user: pick(users), actor: 'lab.contractor', role: 'Owner' }); }
for (let i = 0; i < 2; i++) { const s = scenario(`priv-custom-${i}`, 'privilege_escalation_custom_role', true), t = startOf(); emit(s, t, { type: 'perm', user: pick(users), actor: 'lab.contractor', role: 'power_user_full_access' }); }

// --- benign
for (let i = 0; i < 5; i++) { const s = scenario(`svc-retry-${i}`, 'service_account_retries', false), t = startOf(); for (let k = 0; k < 8; k++) emit(s, t + k * 20_000, { type: 'fail', user: 'lab.svc-sync', ip: '10.0.0.5' }); }
for (let i = 0; i < 4; i++) { const s = scenario(`vacation-${i}`, 'forgotten_password', false), t = startOf(), u = pick(users), ip = ips(); for (let k = 0; k < 6; k++) emit(s, t + k * 40_000, { type: 'fail', user: u, ip }); emit(s, t + 6 * 40_000 + 300_000, { type: 'ok', user: u, ip }); }
for (let i = 0; i < 4; i++) { const s = scenario(`deploy-denials-${i}`, 'deployment_permission_errors', false), t = startOf(), u = pick(users); for (let k = 0; k < 4; k++) emit(s, t + k * 15_000, { type: 'deny', user: u, ip: ips(), resource: '/reports/export' }); }
for (let i = 0; i < 10; i++) { const s = scenario(`typo-${i}`, 'typo', false), t = startOf(), u = pick(users), ip = ips(); for (let k = 0; k < int(1, 3); k++) emit(s, t + k * 30_000, { type: 'fail', user: u, ip }); emit(s, t + 150_000, { type: 'ok', user: u, ip }); }
for (let i = 0; i < 6; i++) { const s = scenario(`onboarding-${i}`, 'routine_role_change', false), t = startOf(); emit(s, t, { type: 'perm', user: pick(users), actor: 'lab.hr-admin', role: 'viewer' }); }
for (let i = 0; i < 6; i++) { const s = scenario(`admin-promo-${i}`, 'approved_admin_promotion', false), t = startOf(); emit(s, t, { type: 'perm', user: pick(users), actor: 'lab.cto', role: 'admin' }); }
for (let i = 0; i < 25; i++) { const s = scenario(`ok-${i}`, 'normal_login', false), t = startOf(); emit(s, t, { type: 'ok', user: pick(users), ip: ips() }); }

writeFileSync(new URL('../../data/synthetic/holdout-events.json', import.meta.url), JSON.stringify(events, null, 1) + '\n');
writeFileSync(new URL('../../data/synthetic/holdout-labels.json', import.meta.url), JSON.stringify(labels, null, 1) + '\n');
console.log(`wrote ${events.length} holdout events, ${Object.keys(labels.scenarios).length} scenarios`);
