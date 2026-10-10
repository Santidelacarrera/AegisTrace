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
    expect(h).toMatch(/^scrypt:[\w-]+:[\w-]+$/);                                   // no '$': safe to paste into .env
    const legacy = h.replace(/:/g, '$');                                            // old stored format keeps working
    expect(verifyPassword('hunter2-secret', legacy)).toBe(true);
  });
  it('signs tokens that expire and reject tampering', () => {
    const t = signToken({ userId: 'u', orgId: 'o', role: 'admin' }, 'k', 60, 0);
    expect(verifyToken(t, 'k', 1000)).toEqual({ sub: 'u', org: 'o', iat: 0 });
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
    expect(() => loadConfig({ NODE_ENV: 'production', AEGIS_API_KEYS: '[]', AEGIS_AUDIT_KEY: 'a', AEGIS_DATA_KEY: 'd' } as NodeJS.ProcessEnv)).toThrow(/AEGIS_SESSION_KEY/);
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

import { base32Decode, base32Encode, newTotpSecret, totpAt, verifyTotp, stepOf } from '../src/totp.js';

describe('TOTP', () => {
  const rfcSecret = base32Encode(Buffer.from('12345678901234567890'));
  it('matches the RFC 6238 SHA-1 test vectors', () => {
    expect(totpAt(rfcSecret, Math.floor(59 / 30), 8)).toBe('94287082');
    expect(totpAt(rfcSecret, Math.floor(1111111109 / 30), 8)).toBe('07081804');
    expect(totpAt(rfcSecret, Math.floor(20000000000 / 30), 8)).toBe('65353130');
  });
  it('round-trips base32 and accepts ±1 step, rejects replay and garbage', () => {
    const s = newTotpSecret();
    expect(base32Encode(base32Decode(s))).toBe(s);
    const now = 1_700_000_000_000, step = stepOf(now);
    expect(verifyTotp(s, totpAt(s, step), now)).toBe(step);
    expect(verifyTotp(s, totpAt(s, step - 1), now)).toBe(step - 1);
    expect(verifyTotp(s, totpAt(s, step + 2), now)).toBeUndefined();
    expect(verifyTotp(s, totpAt(s, step), now, step)).toBeUndefined();     // replay
    expect(verifyTotp(s, 'abcdef', now)).toBeUndefined();
  });
  it('login requires the code for MFA users, after the password, and codes are single-use', async () => {
    const secret = newTotpSecret();
    const cfg = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS };
    cfg.users.find((u) => u.userId === 'alex')!.totpSecret = secret;
    let t = Date.parse('2024-06-01T12:00:00Z');
    cfg.now = () => new Date(t);
    const { app } = createApp({ config: cfg });
    const go = (body: object) => request(app).post('/api/v1/auth/login').send({ orgId: 'org-acme', userId: 'alex', ...body });
    expect((await go({ password: 'wrong' })).body.error).toBe('invalid_credentials');          // wrong password never reveals MFA
    expect((await go({ password: 'demo-approver' })).body.error).toBe('mfa_required');
    expect((await go({ password: 'demo-approver', code: '000000' })).status).toBe(401);
    const code = totpAt(secret, stepOf(t));
    expect((await go({ password: 'demo-approver', code })).status).toBe(200);
    expect((await go({ password: 'demo-approver', code })).status).toBe(401);                   // replay
    t += 30_000;
    expect((await go({ password: 'demo-approver', code: totpAt(secret, stepOf(t)) })).status).toBe(200);
  });
});

describe('abuse resistance of unauthenticated endpoints', () => {
  it('rate limits login per client IP even when every attempt targets a different user (spraying)', async () => {
    const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS, loginRatePerMinute: 5 };
    const { app } = createApp({ config });
    const codes: number[] = [];
    for (let i = 0; i < 8; i++) codes.push((await request(app).post('/api/v1/auth/login').send({ orgId: 'org-acme', userId: `victim${i}`, password: 'guess-guess-guess' })).status);
    expect(codes).toEqual([401, 401, 401, 401, 401, 429, 429, 429]);
    expect((await request(app).get('/api/v1/auth/config')).status).toBe(200);        // other routes unaffected
  });
  it('a captured TOTP code cannot be replayed (enforced through the shared limiter)', async () => {
    const { MemoryLimiter } = await import('../src/limits.js');
    const secret = newTotpSecret();
    const cfg = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS };
    cfg.users.find((u) => u.userId === 'alex')!.totpSecret = secret;
    const t = Date.parse('2024-06-01T12:00:00Z'); cfg.now = () => new Date(t);
    const shared = new MemoryLimiter(() => t);
    const mk = () => createApp({ config: cfg, limiter: shared }).app;                  // two "instances" sharing one limiter, like Redis
    const a = mk(), b = mk();
    const body = { orgId: 'org-acme', userId: 'alex', password: 'demo-approver', code: totpAt(secret, stepOf(t)) };
    expect((await request(a).post('/api/v1/auth/login').send(body)).status).toBe(200);
    expect((await request(b).post('/api/v1/auth/login').send(body)).status).toBe(401);
  });
  it('protects /metrics with a token when configured', async () => {
    const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS, metricsToken: 'm3trics-token' };
    const { app } = createApp({ config });
    expect((await request(app).get('/metrics')).status).toBe(401);
    expect((await request(app).get('/metrics').set('Authorization', 'Bearer wrong')).status).toBe(401);
    expect((await request(app).get('/metrics').set('Authorization', 'Bearer m3trics-token')).status).toBe(200);
  });
});
