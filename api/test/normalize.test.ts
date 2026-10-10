import { describe, expect, it } from 'vitest';
import { normalizeEvent, parseCsv } from '../src/normalize.js';

describe('normalizeEvent', () => {
  it('maps aliases and normalizes timestamp, user, type', () => {
    const r = normalizeEvent({ time: '2024-06-01T10:00:00+02:00', service: 'AUTH', event: 'Failed-Login', username: 'LAB.Alice', src_ip: '203.0.113.5' }, 'o');
    expect(r).toMatchObject({ ok: true, event: { timestamp: '2024-06-01T08:00:00.000Z', source: 'auth', type: 'login_failed', user: 'lab.alice', ip: '203.0.113.5', severity: 'low' } });
  });
  it('accepts epoch seconds and milliseconds', () => {
    const a = normalizeEvent({ ts: 1717236000, source: 's', type: 'login' }, 'o');
    const b = normalizeEvent({ ts: 1717236000000, source: 's', type: 'login' }, 'o');
    expect(a.ok && b.ok && a.event.timestamp === b.event.timestamp).toBe(true);
  });
  it.each([
    [{ source: 's', type: 't' }, 'timestamp is required'],
    [{ timestamp: 'yesterday', source: 's', type: 't' }, 'timestamp is not a valid date'],
    [{ timestamp: '2024-06-01', type: 't' }, 'source is required'],
    [{ timestamp: '2024-06-01', source: 's', type: 't', ip: '999.1.1.1' }, 'ip is not a valid IPv4/IPv6 address'],
    [{ timestamp: '2024-06-01', source: 's', type: 't', severity: 'apocalyptic' }, 'severity must be one of info, low, medium, high, critical'],
    ['nope', 'event must be an object'],
  ])('rejects invalid input %#', (raw, error) => {
    expect(normalizeEvent(raw, 'o')).toEqual({ ok: false, error });
  });
  it('strips control characters, truncates, and derives a stable content id', () => {
    const raw = { timestamp: '2024-06-01', source: 's', type: 'x', message: 'a\u0000b\u001b[31m' + 'z'.repeat(1000) };
    const a = normalizeEvent(raw, 'o'), b = normalizeEvent(raw, 'o');
    expect(a.ok && a.event.attrs.message!.length).toBeLessThanOrEqual(512);
    expect(a.ok && a.event.attrs.message).not.toMatch(/\u0000|\u001b/);
    expect(a.ok && b.ok && a.event.id === b.event.id && a.event.id.startsWith('evt_')).toBe(true);
  });
});

describe('parseCsv', () => {
  it('handles quotes, commas, escaped quotes and CRLF', () => {
    const rows = parseCsv('timestamp,source,type,message\r\n2024-06-01,auth,login_failed,"hello, ""world"""\r\n');
    expect(rows).toEqual([{ timestamp: '2024-06-01', source: 'auth', type: 'login_failed', message: 'hello, "world"' }]);
  });
});
