// Deterministic synthetic dataset (seeded PRNG). All identities and IPs are fictional / documentation ranges.
import { writeFileSync } from 'node:fs';
import { Labels } from '../src/evaluation.js';

let seed = 20240607;
const rnd = () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const int = (a: number, b: number) => a + Math.floor(rnd() * (b - a + 1));
const pick = <T>(xs: T[]) => xs[int(0, xs.length - 1)]!;

const events: Record<string, string>[] = [];
const labels: Labels = { scenarios: {}, events: {} };
let n = 0;
const T0 = Date.parse('2024-06-01T08:00:00Z');
const users = ['lab.alice', 'lab.bob', 'lab.carol', 'lab.dave', 'lab.erin', 'lab.frank', 'lab.grace', 'lab.heidi'];
const resources = ['/api/payroll', '/api/admin/users', '/api/billing', '/api/reports', '/api/keys', '/api/export'];
const ip = () => `203.0.113.${int(1, 250)}`;

function emit(scn: string, offsetMs: number, e: Record<string, string>) {
  const id = `s-${String(++n).padStart(5, '0')}`;
  events.push({ id, timestamp: new Date(T0 + offsetMs).toISOString(), source: e.source ?? 'auth-service', ...e });
  labels.events[id] = scn;
}
const scenario = (id: string, kind: string, malicious: boolean) => { labels.scenarios[id] = { kind, malicious }; return id; };
let slot = 0; // each scenario gets its own 2-hour slot so they never correlate by accident
const startOf = () => (slot++) * 2 * 3600_000;

for (let i = 0; i < 4; i++) { // brute force
  const s = scenario(`brute-${i}`, 'brute_force', true), t = startOf(), u = pick(users), a = ip();
  for (let k = 0; k < int(6, 12); k++) emit(s, t + k * int(5, 40) * 1000, { type: 'login_failed', user: u, ip: a });
}
for (let i = 0; i < 3; i++) { // compromise: failures then success
  const s = scenario(`compromise-${i}`, 'compromise', true), t = startOf(), u = pick(users), a = ip();
  for (let k = 0; k < 7; k++) emit(s, t + k * 20_000, { type: 'login_failed', user: u, ip: a });
  emit(s, t + 7 * 20_000 + 60_000, { type: 'login_success', user: u, ip: a });
}
for (let i = 0; i < 3; i++) { // password spraying
  const s = scenario(`spray-${i}`, 'spraying', true), t = startOf(), a = ip();
  for (let k = 0; k < 10; k++) emit(s, t + k * 15_000, { type: 'login_failed', user: users[k % 5]!, ip: a });
}
for (let i = 0; i < 4; i++) { // authorization probing
  const s = scenario(`probe-${i}`, 'authz_probe', true), t = startOf(), u = pick(users), a = ip();
  for (let k = 0; k < int(4, 8); k++) emit(s, t + k * 30_000, { type: 'authz_denied', user: u, ip: a, resource: resources[k % resources.length]!, source: 'api-gateway' });
}
for (let i = 0; i < 3; i++) { // privilege escalation
  const s = scenario(`priv-${i}`, 'privilege_escalation', true), t = startOf(), u = pick(users);
  emit(s, t, { type: 'permission_change', user: u, ip: ip(), actor: u, new_role: 'admin', source: 'iam' });
}
// benign noise and near-misses
for (let i = 0; i < 12; i++) { // typos: 2-4 failures then success (below threshold)
  const s = scenario(`typo-${i}`, 'typo', false), t = startOf(), u = pick(users), a = ip();
  for (let k = 0; k < int(2, 4); k++) emit(s, t + k * 25_000, { type: 'login_failed', user: u, ip: a });
  emit(s, t + 120_000, { type: 'login_success', user: u, ip: a });
}
for (let i = 0; i < 8; i++) { // one or two denied requests
  const s = scenario(`denied-${i}`, 'single_denial', false), t = startOf();
  for (let k = 0; k < int(1, 2); k++) emit(s, t + k * 60_000, { type: 'authz_denied', user: pick(users), ip: ip(), resource: pick(resources), source: 'api-gateway' });
}
for (let i = 0; i < 6; i++) { // slow failures spread far apart (not a burst)
  const s = scenario(`slow-${i}`, 'slow_failures', false), t = startOf(), u = pick(users), a = ip();
  for (let k = 0; k < 6; k++) emit(s, t + k * 12 * 60_000, { type: 'login_failed', user: u, ip: a });
}
for (let i = 0; i < 8; i++) { // routine low-risk role changes by a distinct admin
  const s = scenario(`rolechg-${i}`, 'routine_role_change', false), t = startOf(), u = pick(users);
  emit(s, t, { type: 'permission_change', user: u, actor: 'lab.admin', new_role: 'viewer', source: 'iam' });
}
for (let i = 0; i < 30; i++) { // routine successful logins
  const s = scenario(`ok-${i}`, 'normal_login', false), t = startOf();
  emit(s, t, { type: 'login_success', user: pick(users), ip: ip() });
}

writeFileSync(new URL('../../data/synthetic/events.json', import.meta.url), JSON.stringify(events, null, 1) + '\n');
writeFileSync(new URL('../../data/synthetic/labels.json', import.meta.url), JSON.stringify(labels, null, 1) + '\n');
console.log(`wrote ${events.length} events, ${Object.keys(labels.scenarios).length} scenarios`);
