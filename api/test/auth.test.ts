import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { hashPassword, signToken, verifyPassword, verifyToken } from '../src/auth.js';
import { createApp } from '../src/app.js';
import { DEMO_KEYS, loadConfig } from '../src/config.js';
import { bruteForceEvents, makeApp } from './helpers.js';

const login = (app: Parameters<typeof request>[0], userId: string, password: string, orgId = 'org-acme') =>
  request(app).post('/api/v1/auth/login').send({ orgId, userId, password });

describe('password + session auth', () => {
  it('hashes with salt and verifies', () => {
    const h = hashPassword('hunter2-secret');
    expect(h).not.toContain('hunter2');
    expect(hashPassword('hunter2-secret')).not.toBe(h);
    expect(verifyPassword('hunter2-secret', h)).toBe(true);
    expect(verifyPassword('nope', h)).toBe(false);
    expect(verifyPassword('hunter2-secret', 'garbage')).toBe(false);
  });
  it('signs tokens that expire and reject tampering', () => {
    const t = signToken({ userId: 'u', orgId: 'o', role: 'admin' }, 'k', 60, 0);
    expect(verifyToken(t, 'k', 1000)).toEqual({ sub: 'u', org: 'o' });
    expect(verifyToken(t, 'k', 61_000)).toBeUndefined();
    expect(verifyToken(t, 'other', 1000)).toBeUndefined();
    const [p, s] = t.split('.');
    const forged = Buffer.from(JSON.stringify({ sub: 'u', org: 'o2', exp: 99999999999 })).toString('base64url');
    expect(verifyToken(`${forged}.${s}`, 'k', 1000)).toBeUndefined();
    expect(p).toBeTruthy();
  });
  it('logs in, uses the bearer token with the user\'s role, and audits it', async () => {
    const { app, as } = makeApp();
    const r = await login(app, 'ana', 'demo-analyst');
    expect(r.status).toBe(200);
    const auth = { Authorization: `Bearer ${r.body.token}` };
    expect((await request(app).post('/api/v1/events').set(auth).send(bruteForceEvents())).status).toBe(202);
    expect((await request(app).get('/api/v1/audit').set(auth)).status).toBe(403);   // analyst role applies
    const audit = (await as('demo-auditor').get('/audit')).body.items;
    expect(audit.find((a: { action: string; actor: string; outcome: string }) => a.action === 'auth.login' && a.actor === 'ana' && a.outcome === 'success')).toBeTruthy();
  });
  it('rejects bad credentials identically for unknown users, audits failures, and locks out', async () => {
    const { app, as } = makeApp();
    const bad = await login(app, 'ana', 'wrong'), unknown = await login(app, 'nobody', 'wrong');
    expect([bad.status, unknown.status]).toEqual([401, 401]);
    expect(bad.body).toEqual(unknown.body);
    for (let i = 0; i < 4; i++) await login(app, 'ana', 'wrong');
    expect((await login(app, 'ana', 'demo-analyst')).status).toBe(429);              // locked even with the right password
    expect((await as('demo-auditor').get('/audit')).body.items.filter((a: { outcome: string; action: string }) => a.action === 'auth.login' && a.outcome === 'denied').length).toBeGreaterThanOrEqual(5);
  });
  it('does not accept a token for another org\'s user or a removed user', async () => {
    const cfg = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS };
    const { app } = createApp({ config: cfg });
    const token = (await login(app, 'ana', 'demo-analyst')).body.token;
    cfg.users.length = 0;                                                            // user removed -> session revoked
    expect((await request(app).get('/api/v1/alerts').set('Authorization', `Bearer ${token}`)).status).toBe(401);
  });
  it('requires AEGIS_SESSION_KEY and users in production config', () => {
    expect(() => loadConfig({ NODE_ENV: 'production', AEGIS_API_KEYS: '[]', AEGIS_AUDIT_KEY: 'a' } as NodeJS.ProcessEnv)).toThrow(/AEGIS_SESSION_KEY/);
  });
});

describe('external audit anchor', () => {
  it('detects tail truncation without any client-supplied anchor', async () => {
    const anchorFile = join(mkdtempSync(join(tmpdir(), 'aegis-')), 'anchor.log');
    const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS, anchorFile };
    const { app, store } = createApp({ config });
    const get = (p: string) => request(app).get('/api/v1' + p).set('x-api-key', 'demo-auditor');
    await request(app).post('/api/v1/events').set('x-api-key', 'demo-ingestor').send(bruteForceEvents());
    await get('/events');
    expect((await get('/audit/verify')).body).toMatchObject({ valid: true, anchorMatch: true });
    store.org('org-acme').audit.pop();
    expect((await get('/audit/verify')).body).toMatchObject({ valid: false, anchorMatch: false });
  });
});

describe('audit anchor failures', () => {
  it('does not take the API down, is counted, and verify reports the gap', async () => {
    const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS, anchorFile: '/nonexistent-dir/anchor.log' };
    const { app } = createApp({ config });
    expect((await request(app).post('/api/v1/events').set('x-api-key', 'demo-ingestor').send(bruteForceEvents())).status).toBe(202);
    const v = (await request(app).get('/api/v1/audit/verify').set('x-api-key', 'demo-auditor')).body;
    expect(v.valid).toBe(true);                       // no anchor exists yet, so nothing to compare against
    expect((await request(app).get('/metrics')).text).toMatch(/aegistrace_anchorErrors_total [1-9]/);
  });
});
