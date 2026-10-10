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

describe.skipIf(!process.env.TEST_DATABASE_URL)('readiness with a database', () => {
  it('reports 503 when PostgreSQL is unreachable', async () => {
    const down = new PgPersistence({ query: async () => { throw new Error('connection refused'); } });
    const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS };
    const { app } = createApp({ config, persistence: down });
    const r = await request(app).get('/ready');
    expect([r.status, r.body.checks.database]).toEqual([503, 'down']);
    expect((await request(app).get('/health')).status).toBe(200);          // liveness is independent
  });
});

describe.skipIf(!process.env.TEST_DATABASE_URL)('users and retention in PostgreSQL', () => {
  it('managed users (with sealed MFA seed) survive a restart, and retention deletes rows from the database', async () => {
    const { default: pg } = await import('pg');
    const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
    await pool.query('DROP TABLE IF EXISTS aegis_doc, aegis_audit');
    const { totpAt, stepOf } = await import('../src/totp.js');
    const day = 86_400_000, T = Date.parse('2025-01-01T00:00:00Z');
    const boot2 = async () => {
      const persistence = new PgPersistence(pool); await persistence.migrate();
      const store = new Store(); await persistence.load(store);
      const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS, retention: { eventDays: 30, incidentDays: 60 }, now: () => new Date(T) };
      return { app: createApp({ config, store, persistence }).app, store };
    };
    const a = await boot2();
    const call = (app: typeof a.app, key: string, path: string, body?: object) => request(app).post('/api/v1' + path).set('x-api-key', key).send(body);
    await call(a.app, 'demo-admin', '/users', { userId: 'persisted', role: 'analyst', password: 'a long enough phrase 1' });
    const t0 = (await request(a.app).post('/api/v1/auth/login').send({ orgId: 'org-acme', userId: 'persisted', password: 'a long enough phrase 1' })).body.token;
    const t1 = (await request(a.app).post('/api/v1/auth/password').set('Authorization', `Bearer ${t0}`).send({ currentPassword: 'a long enough phrase 1', newPassword: 'a different long phrase 2' })).body.token;
    const secret = (await request(a.app).post('/api/v1/auth/mfa/enroll').set('Authorization', `Bearer ${t1}`).send({ password: 'a different long phrase 2' })).body.secret;
    await request(a.app).post('/api/v1/auth/mfa/confirm').set('Authorization', `Bearer ${t1}`).send({ code: totpAt(secret, stepOf(T)) });
    await call(a.app, 'demo-ingestor', '/events', Array.from({ length: 5 }, (_, i) => ({ id: `old${i}`, timestamp: new Date(T - 100 * day + i).toISOString(), source: 's', type: 'login_success', user: 'u' })));
    const count = async (c: string) => Number((await pool.query('SELECT count(*) FROM aegis_doc WHERE collection=$1', [c])).rows[0].count);
    expect(await count('events')).toBe(5);

    const b = await boot2();                                                    // restart
    const login = await request(b.app).post('/api/v1/auth/login').send({ orgId: 'org-acme', userId: 'persisted', password: 'a different long phrase 2' });
    expect(login.body.error).toBe('mfa_required');                              // MFA state came back
    const ok = await request(b.app).post('/api/v1/auth/login').send({ orgId: 'org-acme', userId: 'persisted', password: 'a different long phrase 2', code: totpAt(secret, stepOf(T)) });
    expect(ok.status).toBe(200);
    expect((await pool.query("SELECT body FROM aegis_doc WHERE collection='users'")).rows[0].body.totpSecret).toMatch(/^enc:v1:/);

    expect((await call(b.app, 'demo-admin', '/admin/retention/run', { dryRun: false })).body.events).toBe(5);
    expect(await count('events')).toBe(0);                                      // gone from the database, not just memory
    await pool.end();
  });
});
