import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { buildChain, canonicalJson, GENESIS_HASH, hashRecord, verifyAnchor, verifyChain, EvidenceInput, EvidenceRecord } from '../src/evidence.js';
import { buildEvidenceBundle, verifyEvidenceBundle } from '../src/forensic.js';
import { makeApp } from './helpers.js';

const input = (i: number): EvidenceInput => ({ at: `2024-06-01T09:0${i}:00Z`, kind: 'event', source: 'auth', actor: 'auth', summary: `e${i}`, refs: [`e${i}`], data: { n: i, nested: { b: 2, a: 1 } } });
const chain = (n = 5) => buildChain(Array.from({ length: n }, (_, i) => input(i + 1)));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const scenario = JSON.parse(readFileSync(new URL('../../data/synthetic/forensic/scenario.json', import.meta.url), 'utf8')) as { events: Record<string, unknown>[] };

describe('canonical JSON and chain primitives', () => {
  it('sorts keys recursively, drops undefined and has no whitespace', () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { y: 1, x: undefined }], c: null } })).toBe('{"a":{"c":null,"d":[3,{"y":1}]},"b":1}');
  });
  it('an empty chain verifies against the genesis hash', () => {
    expect(verifyChain([])).toEqual({ valid: true, entries: 0, head: GENESIS_HASH });
  });
  it('a fresh chain verifies, starts at seq 1 and links to the genesis hash', () => {
    const c = chain();
    expect(c[0]!.prev).toBe(GENESIS_HASH);
    expect(c.map((r) => r.seq)).toEqual([1, 2, 3, 4, 5]);
    expect(verifyChain(c)).toEqual({ valid: true, entries: 5, head: c[4]!.hash });
  });
  it('is deterministic: the same inputs give the same hashes regardless of object key order', () => {
    const a = buildChain([{ ...input(1), data: { x: 1, y: 2 } }]);
    const b = buildChain([{ ...input(1), data: { y: 2, x: 1 } }]);
    expect(a[0]!.hash).toBe(b[0]!.hash);
  });
});

describe('alteration detection (exact position and reason)', () => {
  it('detects an edited field in the middle of the chain', () => {
    const c = clone(chain());
    c[2]!.summary = 'changed by an attacker';
    expect(verifyChain(c)).toMatchObject({ valid: false, brokenAt: 3, reason: 'hash_mismatch' });
  });
  it('detects an edited nested value (e.g. an IP inside data)', () => {
    const c = clone(chain());
    (c[3]!.data as { nested: { a: number } }).nested.a = 999;
    expect(verifyChain(c)).toMatchObject({ valid: false, brokenAt: 4, reason: 'hash_mismatch' });
  });
  it('detects a deleted record (sequence gap)', () => {
    const c = clone(chain());
    c.splice(2, 1);
    expect(verifyChain(c)).toMatchObject({ valid: false, brokenAt: 3, reason: 'seq_gap' });
  });
  it('detects reordered records', () => {
    const c = clone(chain());
    [c[1], c[2]] = [c[2]!, c[1]!];
    expect(verifyChain(c)).toMatchObject({ valid: false, brokenAt: 2, reason: 'seq_gap' });
  });
  it('detects a record re-hashed in isolation (wrong prev for its position) at its own position', () => {
    const c = clone(chain());
    c[1]!.summary = 'edited';
    const { hash: _h, ...body } = c[1]!;
    c[1]!.hash = buildChain([body as EvidenceInput])[0]!.hash;   // hashed as if it were first, so prev is wrong
    expect(verifyChain(c)).toMatchObject({ valid: false, brokenAt: 2, reason: 'hash_mismatch' });
  });
  it('detects an edit whose hash was recomputed correctly but whose successor still links to the old hash', () => {
    const c = clone(chain());
    c[1]!.summary = 'edited';
    const { hash: _h, ...body } = c[1]!;
    c[1]!.hash = hashRecord(body);            // correct for its real position
    expect(verifyChain(c)).toMatchObject({ valid: false, brokenAt: 3, reason: 'prev_mismatch' });
  });
  it('detects a forged genesis', () => {
    const c = clone(chain());
    c[0]!.prev = '1'.repeat(64);
    expect(verifyChain(c)).toMatchObject({ valid: false, brokenAt: 1, reason: 'genesis_mismatch' });
  });
  it('rejects malformed records without throwing', () => {
    expect(verifyChain([null])).toMatchObject({ valid: false, reason: 'malformed' });
    expect(verifyChain(['x'])).toMatchObject({ valid: false, reason: 'malformed' });
  });
});

describe('limits: what the chain alone cannot prove, and what an external anchor adds', () => {
  it('truncating the tail verifies locally...', () => {
    const c = clone(chain());
    c.pop();
    expect(verifyChain(c).valid).toBe(true);
  });
  it('...but is caught by comparing with a published anchor', () => {
    const full = verifyChain(chain());
    const c = clone(chain());
    c.pop();
    expect(verifyAnchor(verifyChain(c), { head: full.head, entries: full.entries })).toMatchObject({ valid: false, reason: 'anchor_mismatch' });
  });
  it('a fully recomputed forgery verifies locally: only an anchor exposes it', () => {
    const forged = buildChain([input(1), { ...input(2), summary: 'forged' }, input(3)]);
    const real = verifyChain(chain(3));
    expect(verifyChain(forged).valid).toBe(true);                                             // the known limit
    expect(verifyAnchor(verifyChain(forged), { head: real.head, entries: real.entries })).toMatchObject({ reason: 'anchor_mismatch' });
  });
});

describe('forensic bundle from the synthetic scenario', () => {
  async function scenarioApp() {
    const ctx = makeApp();
    await ctx.as('demo-ingestor').post('/events', scenario.events);
    const id = (await ctx.as('demo-analyst').get('/incidents')).body.items[0].id as string;
    await ctx.as('demo-analyst').post(`/incidents/${id}/status`, { status: 'triaging', reason: 'review' });
    await ctx.as('demo-analyst').post(`/incidents/${id}/comments`, { text: 'Check with the owner' });
    return { ...ctx, id };
  }

  it('returns a verifiable bundle with events, alerts, analysis-free activity, in time order', async () => {
    const { as, id } = await scenarioApp();
    const r = await as('demo-auditor').get(`/incidents/${id}/evidence`);
    expect(r.status).toBe(200);
    const b = r.body;
    expect(verifyEvidenceBundle(b)).toMatchObject({ valid: true, entries: b.entries, head: b.head });
    expect(b.records.filter((x: EvidenceRecord) => x.kind === 'event')).toHaveLength(8);
    expect(b.records.some((x: EvidenceRecord) => x.kind === 'alert' && x.data.ruleId === 'R002')).toBe(true);
    expect(b.records.some((x: EvidenceRecord) => x.kind === 'activity' && x.summary === 'Check with the owner')).toBe(true);
    const times = b.records.map((x: EvidenceRecord) => x.at);
    expect([...times].sort()).toEqual(times);
    expect(b.missing).toEqual([]);
  });

  it('keeps the untrusted log message as data, never as instructions or as a summary field', async () => {
    const { as, id } = await scenarioApp();
    const b = (await as('demo-auditor').get(`/incidents/${id}/evidence`)).body;
    const ev = b.records.find((x: EvidenceRecord) => x.kind === 'event' && x.refs[0] === 'fx-001');
    expect(ev.data.attrs.message).toMatch(/Password incorrect/);
    expect(ev.summary).not.toMatch(/Password incorrect/);
  });

  it('two exports of the same state produce identical records and head (only generatedAt differs)', async () => {
    const { as, id } = await scenarioApp();
    const a = (await as('demo-auditor').get(`/incidents/${id}/evidence`)).body;
    const b = (await as('demo-auditor').get(`/incidents/${id}/evidence`)).body;
    expect(a.records).toEqual(b.records);
    expect(a.head).toBe(b.head);
  });

  it('detects an altered bundle file, a claimed head that does not match, and a malformed file', async () => {
    const { as, id } = await scenarioApp();
    const good = (await as('demo-auditor').get(`/incidents/${id}/evidence`)).body;
    const bad = clone(good);
    bad.records[4].data.ip = '203.0.113.99';
    expect(verifyEvidenceBundle(bad)).toMatchObject({ valid: false, brokenAt: 5, reason: 'hash_mismatch' });
    const lie = clone(good);
    lie.head = '0'.repeat(64);
    expect(verifyEvidenceBundle(lie)).toMatchObject({ valid: false, reason: 'claimed_head_mismatch' });
    expect(verifyEvidenceBundle({ format: 'other' })).toMatchObject({ valid: false, reason: 'malformed' });
  });

  it('records what it could not resolve instead of hiding it (e.g. events removed by retention)', async () => {
    const { store, id } = await scenarioApp();
    const org = store.org('org-acme');
    org.events.delete('fx-003');
    const inc = org.incidents.get(id)!;
    const b = buildEvidenceBundle(org, inc, 'org-acme', '2024-06-01T10:00:00Z', 'x');
    expect(b.missing).toEqual(['event:fx-003']);
    expect(verifyEvidenceBundle(b).valid).toBe(true);
  });

  it('is isolated by organization and restricted to auditors and admins; exports are audited', async () => {
    const { as, id } = await scenarioApp();
    expect((await as('demo-other-admin').get(`/incidents/${id}/evidence`)).status).toBe(404);
    expect((await as('demo-analyst').get(`/incidents/${id}/evidence`)).status).toBe(403);
    expect((await as('demo-viewer').get(`/incidents/${id}/evidence`)).status).toBe(403);
    const audit = (await as('demo-auditor').get('/audit')).body.items;
    expect(audit.some((a: { action: string }) => a.action === 'incident.evidence')).toBe(true);
  });

  it('the committed example bundle is genuine and its tampered copy is detected', () => {
    const genuine = JSON.parse(readFileSync(new URL('../../docs/examples/evidence-bundle.json', import.meta.url), 'utf8'));
    const tampered = JSON.parse(readFileSync(new URL('../../docs/examples/evidence-bundle.tampered.json', import.meta.url), 'utf8'));
    expect(verifyEvidenceBundle(genuine).valid).toBe(true);
    expect(verifyEvidenceBundle(tampered)).toMatchObject({ valid: false, brokenAt: 4, reason: 'hash_mismatch' });
  });
});
