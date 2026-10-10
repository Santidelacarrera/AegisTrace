import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { DEMO_KEYS, loadConfig } from '../src/config.js';
import { PgPersistence, Queryable } from '../src/persistence.js';
import { Store } from '../src/store.js';
import { bruteForceEvents } from './helpers.js';

async function boot(db: Queryable) {
  const persistence = new PgPersistence(db);
  await persistence.migrate();
  const store = new Store();
  await persistence.load(store);
  const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS };
  const { app } = createApp({ config, store, persistence });
  const as = (key: string) => ({
    get: (u: string) => request(app).get('/api/v1' + u).set('x-api-key', key),
    post: (u: string, b?: unknown) => request(app).post('/api/v1' + u).set('x-api-key', key).send(b as object),
  });
  return { as, store };
}

async function scenario(db: Queryable) {
  const a = await boot(db);
  await a.as('demo-ingestor').post('/events', bruteForceEvents());
  const id = (await a.as('demo-analyst').get('/incidents')).body.items[0].id;
  await a.as('demo-analyst').post(`/incidents/${id}/status`, { status: 'triaging' });
  const analysis = (await a.as('demo-analyst').post(`/incidents/${id}/analysis`)).body;
  const act = (await a.as('demo-analyst').post(`/incidents/${id}/actions`, { recommendationId: analysis.recommendations.find((r: { executable: boolean }) => r.executable).id })).body;
  await a.as('demo-approver').post(`/actions/${act.id}/approve`);
  const before = (await a.as('demo-auditor').get('/audit/verify')).body;

  const b = await boot(db);                                   // simulated restart: fresh process, same database
  const inc = (await b.as('demo-analyst').get(`/incidents/${id}`)).body;
  expect(inc.incident.status).toBe('triaging');
  expect(inc.evidence).toHaveLength(7);
  expect(inc.analyses).toHaveLength(1);
  expect(inc.actions[0].status).toBe('executed');
  expect((await b.as('demo-analyst').get('/lab-state')).body.blockedIps).toEqual(['203.0.113.9']);
  const after = (await b.as('demo-auditor').get('/audit/verify')).body;
  expect(after.valid).toBe(true);
  expect(after.head).not.toBe('');
  expect(after.entries).toBeGreaterThanOrEqual(before.entries);   // reads after restart append to the same chain
  expect((await b.as('demo-ingestor').post('/events', bruteForceEvents())).body.duplicates).toBe(7);  // dedupe survives restart
  expect((await b.as('demo-other-admin').get('/incidents')).body.total).toBe(0);
}

describe('PostgreSQL persistence', () => {
  it.skipIf(!process.env.TEST_DATABASE_URL)('survives a restart (PostgreSQL, set TEST_DATABASE_URL)', async () => {
    const { default: pg } = await import('pg');
    const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
    await pool.query('DROP TABLE IF EXISTS aegis_doc, aegis_audit');
    await scenario(pool);
    await pool.end();
  });
});
