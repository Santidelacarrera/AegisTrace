// Regenerates docs/examples/ from the synthetic forensic scenario. The clock is fixed, so output is reproducible.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { DEMO_KEYS, loadConfig } from '../src/config.js';
import { verifyEvidenceBundle } from '../src/forensic.js';

const root = new URL('../../', import.meta.url);
const scenario = JSON.parse(readFileSync(new URL('data/synthetic/forensic/scenario.json', root), 'utf8')) as { events: unknown[] };
const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS, now: () => new Date('2024-06-01T09:30:00Z') };
const { app } = createApp({ config });
const call = (key: string) => ({
  get: (p: string) => request(app).get('/api/v1' + p).set('x-api-key', key),
  post: (p: string, body?: unknown) => request(app).post('/api/v1' + p).set('x-api-key', key).send(body as object),
});

await call('demo-ingestor').post('/events', scenario.events);
const id = (await call('demo-analyst').get('/incidents')).body.items[0].id as string;
await call('demo-analyst').post(`/incidents/${id}/status`, { status: 'triaging', reason: 'forensic review opened' });
await call('demo-analyst').post(`/incidents/${id}/comments`, { text: 'Confirm with the account owner before containment.' });
const bundle = (await call('demo-auditor').get(`/incidents/${id}/evidence`)).body;

// Same bundle with one byte changed in record 4 (an IP), to show what a verifier reports.
const tampered = JSON.parse(JSON.stringify(bundle));
tampered.records[3].data.ip = '203.0.113.99';

mkdirSync(new URL('docs/examples/', root), { recursive: true });
writeFileSync(new URL('docs/examples/evidence-bundle.json', root), JSON.stringify(bundle, null, 2) + '\n');
writeFileSync(new URL('docs/examples/evidence-bundle.tampered.json', root), JSON.stringify(tampered, null, 2) + '\n');
console.log('genuine :', JSON.stringify(verifyEvidenceBundle(bundle)));
console.log('tampered:', JSON.stringify(verifyEvidenceBundle(tampered)));
