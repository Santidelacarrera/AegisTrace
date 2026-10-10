import { describe, expect, it } from 'vitest';
import { detect } from '../src/rules.js';
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
  it('R001 does not fire for failures spread beyond the window', () => {
    const slow = norm(Array.from({ length: 8 }, (_, i) => ev(`a${i}`, i * 6, { type: 'login_failed', user: 'u', ip: '203.0.113.1' })));
    expect(detect(slow)).toEqual([]);
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
