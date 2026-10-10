import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { evaluate, Labels } from '../src/evaluation.js';

const dir = new URL('../../data/synthetic/', import.meta.url);
describe('synthetic dataset evaluation', () => {
  it('meets precision/recall targets and reports no missed scenarios', () => {
    const events = JSON.parse(readFileSync(new URL('events.json', dir), 'utf8'));
    const labels = JSON.parse(readFileSync(new URL('labels.json', dir), 'utf8')) as Labels;
    const r = evaluate(events, labels);
    expect(r.precision).toBeGreaterThanOrEqual(0.9);
    expect(r.recall).toBeGreaterThanOrEqual(0.9);
    expect(r.missed).toEqual([]);
  });
});

describe('holdout dataset (not used for tuning)', () => {
  it('pins the documented, deliberately unflattering numbers so the README cannot silently drift', () => {
    const events = JSON.parse(readFileSync(new URL('holdout-events.json', dir), 'utf8'));
    const labels = JSON.parse(readFileSync(new URL('holdout-labels.json', dir), 'utf8')) as Labels;
    const r = evaluate(events, labels);
    expect(r.precision).toBeCloseTo(0.439, 2);
    expect(r.recall).toBeCloseTo(0.652, 2);
    expect(Object.keys(r.missedByKind).sort()).toEqual(['credential_stuffing', 'low_and_slow_brute_force', 'privilege_escalation_custom_role']);
  });
});
