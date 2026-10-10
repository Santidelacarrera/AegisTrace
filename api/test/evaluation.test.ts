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

import { EMPTY_CONTEXT } from '../src/rules.js';

const ctx = {
  holdout: { serviceAccounts: ['lab.svc-*'], changeApprovers: ['lab.cto', 'lab.hr-admin'] },
  holdout2: { serviceAccounts: ['svc-*', 'ci-*', '*-bot'], changeApprovers: ['staff.vp-eng', 'staff.hr'] },
};
const run = (prefix: string, c = EMPTY_CONTEXT) =>
  evaluate(JSON.parse(readFileSync(new URL(`${prefix}events.json`, dir), 'utf8')), JSON.parse(readFileSync(new URL(`${prefix}labels.json`, dir), 'utf8')) as Labels, 'medium', c);

describe('holdout datasets: documented numbers are pinned so the README cannot silently drift', () => {
  it('holdout 1 (used for tuning, so no longer independent)', () => {
    const a = run('holdout-'), b = run('holdout-', ctx.holdout);
    expect([a.precision, a.recall]).toEqual([expect.closeTo(0.531, 2), 1]);
    expect([b.precision, b.recall]).toEqual([expect.closeTo(0.684, 2), 1]);
  });
  it('holdout 2 (written after tuning; the representative numbers)', () => {
    const a = run('holdout2-'), b = run('holdout2-', ctx.holdout2);
    expect([a.precision, a.recall]).toEqual([expect.closeTo(0.441, 2), expect.closeTo(0.813, 2)]);
    expect([b.precision, b.recall]).toEqual([expect.closeTo(0.619, 2), expect.closeTo(0.813, 2)]);
    expect(Object.keys(b.missedByKind).sort()).toEqual(['credential_stuffing_small', 'glacial_brute_force_9min']);
  });
});
