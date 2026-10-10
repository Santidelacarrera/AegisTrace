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
