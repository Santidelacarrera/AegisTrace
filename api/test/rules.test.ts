import { describe, expect, it } from 'vitest';
import { detect, matchesAny } from '../src/rules.js';
import { normalizeEvent } from '../src/normalize.js';
import { bruteForceEvents, iso } from './helpers.js';

const norm = (raws: Record<string, unknown>[]) => raws.map((r) => { const n = normalizeEvent(r, 'o'); if (!n.ok) throw new Error(n.error); return n.event; });
const ev = (id: string, min: number, extra: Record<string, unknown>) => ({ id, timestamp: iso(min), source: 'auth', ...extra });

describe('detection rules', () => {
  it('R001 fires at the threshold and not below it', () => {
    const five = norm(Array.from({ length: 5 }, (_, i) => ev(`a${i}`, i, { type: 'login_failed', user: 'u', ip: '203.0.113.1' })));
    const four = five.slice(0, 4);
    expect(detect(five).map((a) => a.ruleId)).toEqual(['R001']);
    expect(detect(four)).toEqual([]);
  });
  it('R001 does not fire for failures spread beyond the window (only the slow rule R004 does)', () => {
    const slow = norm(Array.from({ length: 8 }, (_, i) => ev(`a${i}`, i * 6, { type: 'login_failed', user: 'u', ip: '203.0.113.1' })));
    expect(detect(slow).map((a) => a.ruleId)).toEqual(['R004']);
    expect(detect(slow.slice(0, 7))).toEqual([]);
  });
  it('R002 critical when a success follows the burst', () => {
    const rules = detect(norm(bruteForceEvents())).map((a) => [a.ruleId, a.severity]);
    expect(rules).toEqual([['R001', 'high'], ['R002', 'critical']]);
  });
  it('R002 does not fire for a success before the burst', () => {
    const evs = norm([ev('s', -30, { type: 'login_success', user: 'lab.alice', ip: '203.0.113.9' }), ...bruteForceEvents('e', false)]);
    expect(detect(evs).map((a) => a.ruleId)).toEqual(['R001']);
  });
  it('R003 detects spraying: one IP, several users', () => {
    const evs = norm(Array.from({ length: 6 }, (_, i) => ev(`p${i}`, i, { type: 'login_failed', user: `u${i % 3}`, ip: '203.0.113.7' })));
    expect(detect(evs).map((a) => a.ruleId)).toEqual(['R003']);
  });
  it('R010 medium at 3 denials, high at 10', () => {
    const mk = (n: number) => norm(Array.from({ length: n }, (_, i) => ev(`z${i}`, i, { type: 'forbidden', user: 'u', resource: `/r${i}` })));
    expect(detect(mk(2))).toEqual([]);
    expect(detect(mk(3))[0]).toMatchObject({ ruleId: 'R010', severity: 'medium' });
    expect(detect(mk(10))[0]).toMatchObject({ ruleId: 'R010', severity: 'high' });
  });
  it('R020 flags admin elevation and self-grants, keeps routine changes low', () => {
    const evs = norm([
      ev('p1', 0, { type: 'role_change', user: 'u', actor: 'boss', new_role: 'admin' }),
      ev('p2', 1, { type: 'role_change', user: 'v', actor: 'v', new_role: 'editor' }),
      ev('p3', 2, { type: 'role_change', user: 'w', actor: 'boss', new_role: 'viewer' }),
    ]);
    expect(detect(evs).map((a) => a.severity)).toEqual(['high', 'high', 'low']);
  });
  it('is deterministic regardless of input order', () => {
    const evs = norm(bruteForceEvents());
    const a = JSON.stringify(detect(evs).map((x) => [x.ruleId, x.events.map((e) => e.id)]));
    const b = JSON.stringify(detect([...evs].reverse()).map((x) => [x.ruleId, x.events.map((e) => e.id)]));
    expect(a).toBe(b);
  });
});


describe('context-aware and added rules', () => {
  const fails = (n: number, gapMin: number, user = 'u', ip = '203.0.113.1', prefix = 'f') =>
    norm(Array.from({ length: n }, (_, i) => ev(`${prefix}${i}`, i * gapMin, { type: 'login_failed', user, ip })));
  it('matchesAny supports exact, prefix*, *suffix and *contains*', () => {
    expect([matchesAny('svc-a', ['svc-*']), matchesAny('a-bot', ['*-bot']), matchesAny('x-ci-y', ['*ci*']), matchesAny('svc', ['svc']), matchesAny('other', ['svc-*']), matchesAny(undefined, ['*'])]).toEqual([true, true, true, true, false, false]);
  });
  it('R004 catches 3.5-minute-cadence guessing that R001 cannot, but not 9-minute cadence', () => {
    expect(detect(fails(11, 3.5)).map((a) => a.ruleId)).toEqual(['R004']);
    expect(detect(fails(9, 9))).toEqual([]);
  });
  it('R004 does not duplicate an R001 burst', () => {
    expect(detect(fails(10, 0.2)).map((a) => a.ruleId)).toEqual(['R001']);
  });
  it('R005 flags many accounts failing at once, from any IPs, and ignores service accounts', () => {
    const many = norm(Array.from({ length: 16 }, (_, i) => ev(`s${i}`, i * 0.1, { type: 'login_failed', user: `u${i}`, ip: `203.0.113.${i}` })));
    expect(detect(many).map((a) => a.ruleId)).toContain('R005');
    const svc = norm(Array.from({ length: 16 }, (_, i) => ev(`b${i}`, i * 0.1, { type: 'login_failed', user: `svc-${i}`, ip: '10.0.0.1' })));
    expect(detect(svc, { serviceAccounts: ['svc-*'], changeApprovers: [] }).filter((a) => a.ruleId === 'R005')).toEqual([]);
  });
  it('configured service accounts lower R001 to low and suppress R002/R004', () => {
    const evs = [...fails(8, 0.2, 'svc-sync', '10.0.0.5'), ...norm([ev('ok', 3, { type: 'login_success', user: 'svc-sync', ip: '10.0.0.5' })])];
    const c = { serviceAccounts: ['svc-*'], changeApprovers: [] };
    expect(detect(evs).map((a) => a.ruleId)).toEqual(['R001', 'R002']);
    expect(detect(evs, c).map((a) => [a.ruleId, a.severity])).toEqual([['R001', 'low']]);
  });
  it('R020 judges role names by pattern, not an exact list', () => {
    const role = (r: string, actor = 'someone') => detect(norm([ev('p', 0, { type: 'role_change', user: 'u', actor, new_role: r })]))[0]!.severity;
    expect([role('org_super_admin'), role('billing_manager'), role('power_user_full_access'), role('devops-lead'), role('viewer'), role('Member')]).toEqual(['high', 'high', 'high', 'medium', 'low', 'low']);
  });
  it('R020: approved changes by a configured approver drop to low, but never self-grants', () => {
    const c = { serviceAccounts: [], changeApprovers: ['cto'] };
    const one = (actor: string, user = 'u') => detect(norm([ev('p', 0, { type: 'role_change', user, actor, new_role: 'admin' })]), c)[0]!;
    expect(one('cto').severity).toBe('low');
    expect(one('cto').explanation).toMatch(/change approver/);
    expect(one('cto', 'cto').severity).toBe('high');
    expect(one('intern').severity).toBe('high');
  });
});
