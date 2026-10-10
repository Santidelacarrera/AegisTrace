import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { totpAt, stepOf } from '../src/totp.js';
import { applyRetention } from '../src/retention.js';
import { OrgData } from '../src/store.js';
import { bruteForceEvents, makeApp } from './helpers.js';

const GOOD = 'correct horse battery';
const login = (app: ReturnType<typeof makeApp>['app'], userId: string, password: string, extra: object = {}) =>
  request(app).post('/api/v1/auth/login').send({ orgId: 'org-acme', userId, password, ...extra });
const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });

async function createUser(ctx: ReturnType<typeof makeApp>, body: object = { userId: 'newbie', role: 'analyst' }) {
  const r = await ctx.as('demo-admin').post('/users', body);
  expect(r.status).toBe(201);
  return r.body as { user: { userId: string }; temporaryPassword?: string };
}

describe('user management', () => {
  it('only admins manage users; creation issues a temporary password once and stores no plaintext', async () => {
    const ctx = makeApp();
    expect((await ctx.as('demo-analyst').post('/users', { userId: 'x1', role: 'viewer' })).status).toBe(403);
    expect((await ctx.as('demo-approver').get('/users')).status).toBe(403);
    const { temporaryPassword, user } = await createUser(ctx);
    expect(temporaryPassword).toHaveLength(20);
    expect(user).toMatchObject({ userId: 'newbie', role: 'analyst', mustChangePassword: true, mfa: false });
    expect(JSON.stringify((await ctx.as('demo-admin').get('/users')).body)).not.toMatch(/passwordHash|scrypt|totpSecret/);
    expect(JSON.stringify([...ctx.store.org('org-acme').users.values()])).not.toContain(temporaryPassword);
    expect((await ctx.as('demo-admin').post('/users', { userId: 'newbie', role: 'viewer' })).status).toBe(409);
    expect((await ctx.as('demo-admin').post('/users', { userId: 'ana', role: 'viewer' })).status).toBe(409);     // collides with a config user
    expect((await ctx.as('demo-admin').post('/users', { userId: 'Bad Id!', role: 'viewer' })).status).toBe(400);
    expect((await ctx.as('demo-admin').post('/users', { userId: 'weakling', role: 'viewer', password: 'short' })).body.error).toBe('weak_password');
  });

  it('a temporary password only allows changing it, and the change voids older tokens', async () => {
    const ctx = makeApp();
    const { temporaryPassword } = await createUser(ctx);
    const first = await login(ctx.app, 'newbie', temporaryPassword!);
    expect(first.body.mustChangePassword).toBe(true);
    const h = bearer(first.body.token);
    expect((await request(ctx.app).get('/api/v1/alerts').set(h)).body.error).toBe('password_change_required');
    expect((await request(ctx.app).get('/api/v1/auth/me').set(h)).body.mustChangePassword).toBe(true);
    expect((await request(ctx.app).post('/api/v1/auth/password').set(h).send({ currentPassword: temporaryPassword, newPassword: 'short' })).body.error).toBe('weak_password');
    expect((await request(ctx.app).post('/api/v1/auth/password').set(h).send({ currentPassword: temporaryPassword, newPassword: 'newbie-is-my-name!' })).body.error).toBe('weak_password');
    expect((await request(ctx.app).post('/api/v1/auth/password').set(h).send({ currentPassword: 'wrong-wrong-wrong', newPassword: GOOD })).status).toBe(401);
    const changed = await request(ctx.app).post('/api/v1/auth/password').set(h).send({ currentPassword: temporaryPassword, newPassword: GOOD });
    expect(changed.status).toBe(200);
    expect((await request(ctx.app).get('/api/v1/alerts').set(h)).status).toBe(401);                       // old token is void
    expect((await request(ctx.app).get('/api/v1/alerts').set(bearer(changed.body.token))).status).toBe(200);
    expect((await login(ctx.app, 'newbie', temporaryPassword!)).status).toBe(401);
    const again = await login(ctx.app, 'newbie', GOOD);
    expect(again.body.mustChangePassword).toBe(false);
  });

  it('admin reset gives a new temporary password and kills existing sessions', async () => {
    const ctx = makeApp();
    const { temporaryPassword } = await createUser(ctx);
    const tok = (await request(ctx.app).post('/api/v1/auth/password').set(bearer((await login(ctx.app, 'newbie', temporaryPassword!)).body.token)).send({ currentPassword: temporaryPassword, newPassword: GOOD })).body.token;
    expect((await request(ctx.app).get('/api/v1/alerts').set(bearer(tok))).status).toBe(200);
    const reset = await ctx.as('demo-admin').post('/users/newbie/reset-password');
    expect(reset.body.temporaryPassword).toHaveLength(20);
    expect((await request(ctx.app).get('/api/v1/alerts').set(bearer(tok))).status).toBe(401);
    expect((await login(ctx.app, 'newbie', GOOD)).status).toBe(401);
    expect((await login(ctx.app, 'newbie', reset.body.temporaryPassword)).body.mustChangePassword).toBe(true);
  });

  it('role changes apply immediately; disabling revokes access; guards protect the last admin and self', async () => {
    const ctx = makeApp();
    const { temporaryPassword } = await createUser(ctx, { userId: 'dana', role: 'viewer', password: GOOD });
    const tok = (await login(ctx.app, 'dana', GOOD)).body.token;
    // must change first? creation with explicit password still forces a change
    expect((await request(ctx.app).get('/api/v1/alerts').set(bearer(tok))).status).toBe(403);
    expect(temporaryPassword).toBeUndefined();
    const t2 = (await request(ctx.app).post('/api/v1/auth/password').set(bearer(tok)).send({ currentPassword: GOOD, newPassword: 'another long phrase 42' })).body.token;
    expect((await request(ctx.app).post('/api/v1/events').set(bearer(t2)).send(bruteForceEvents())).status).toBe(403);
    await ctx.as('demo-admin').post('/users/dana/role', { role: 'ingestor' });
    expect((await request(ctx.app).post('/api/v1/events').set(bearer(t2)).send(bruteForceEvents())).status).toBe(202);
    await ctx.as('demo-admin').post('/users/dana/disable');
    expect((await request(ctx.app).post('/api/v1/events').set(bearer(t2)).send(bruteForceEvents('z'))).status).toBe(401);
    expect((await login(ctx.app, 'dana', 'another long phrase 42')).status).toBe(401);
    expect((await ctx.as('demo-admin').post('/users/dana/enable')).body.disabled).toBe(false);
    expect((await login(ctx.app, 'dana', 'another long phrase 42')).status).toBe(200);
    expect((await ctx.as('demo-admin').post('/users/root-admin/disable')).body.error).toBe('managed_by_config');
    expect((await ctx.as('demo-admin').post('/users/nobody/disable')).status).toBe(404);
    // an API-created admin can't demote or disable themself
    await createUser(ctx, { userId: 'boss', role: 'admin', password: GOOD });
    const bt = (await request(ctx.app).post('/api/v1/auth/password').set(bearer((await login(ctx.app, 'boss', GOOD)).body.token)).send({ currentPassword: GOOD, newPassword: 'yet another phrase 99' })).body.token;
    const bossReq = (path: string, body?: object) => request(ctx.app).post('/api/v1' + path).set(bearer(bt)).send(body);
    expect((await bossReq('/users/boss/disable')).body.error).toBe('self_change');
    expect((await bossReq('/users/boss/role', { role: 'viewer' })).body.error).toBe('self_change');
  });

  it('keeps users and their sessions isolated per organization', async () => {
    const ctx = makeApp();
    await createUser(ctx, { userId: 'shared-name', role: 'viewer', password: GOOD });
    expect((await ctx.as('demo-other-admin').get('/users')).body.items.some((u: { userId: string }) => u.userId === 'shared-name')).toBe(false);
    expect((await ctx.as('demo-other-admin').post('/users/shared-name/disable')).status).toBe(404);
    expect((await request(ctx.app).post('/api/v1/auth/login').send({ orgId: 'org-globex', userId: 'shared-name', password: GOOD })).status).toBe(401);
  });

  it('audits every management action', async () => {
    const ctx = makeApp();
    await createUser(ctx);
    await ctx.as('demo-admin').post('/users/newbie/role', { role: 'viewer' });
    await ctx.as('demo-admin').post('/users/newbie/reset-password');
    const actions = (await ctx.as('demo-auditor').get('/audit')).body.items.map((a: { action: string }) => a.action);
    expect(actions).toEqual(expect.arrayContaining(['user.create', 'user.role', 'user.reset_password']));
  });
});

describe('MFA self-service and recovery codes', () => {
  async function activeUser(ctx: ReturnType<typeof makeApp>) {
    await createUser(ctx, { userId: 'mia', role: 'analyst', password: GOOD });
    const t0 = (await login(ctx.app, 'mia', GOOD)).body.token;
    const token = (await request(ctx.app).post('/api/v1/auth/password').set(bearer(t0)).send({ currentPassword: GOOD, newPassword: 'long phrases are great 7' })).body.token;
    return { token, password: 'long phrases are great 7' };
  }
  it('enroll -> confirm -> login needs a code; recovery codes work once; the seed is sealed at rest', async () => {
    const ctx = makeApp();
    const { token, password } = await activeUser(ctx);
    const h = bearer(token);
    expect((await request(ctx.app).post('/api/v1/auth/mfa/enroll').set(h).send({ password: 'nope-nope-nope' })).status).toBe(401);
    const enroll = (await request(ctx.app).post('/api/v1/auth/mfa/enroll').set(h).send({ password })).body;
    expect(enroll.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
    expect(JSON.stringify([...ctx.store.org('org-acme').users.values()])).not.toContain(enroll.secret);   // sealed, not plaintext
    expect((await request(ctx.app).post('/api/v1/auth/mfa/confirm').set(h).send({ code: '000000' })).status).toBe(401);
    const confirm = await request(ctx.app).post('/api/v1/auth/mfa/confirm').set(h).send({ code: totpAt(enroll.secret, stepOf(ctx.config.now().getTime())) });
    expect(confirm.status).toBe(200);
    const codes: string[] = confirm.body.recoveryCodes;
    expect(codes).toHaveLength(10);
    expect((await login(ctx.app, 'mia', password)).body.error).toBe('mfa_required');
    expect((await login(ctx.app, 'mia', password, { code: '123456' })).status).toBe(401);
    const viaRecovery = await login(ctx.app, 'mia', password, { code: codes[0] });
    expect(viaRecovery.status).toBe(200);
    expect((await login(ctx.app, 'mia', password, { code: codes[0] })).status).toBe(401);                  // single use
    expect((await login(ctx.app, 'mia', password, { code: codes[1] })).status).toBe(200);
    const audit = (await ctx.as('demo-auditor').get('/audit')).body.items;
    expect(audit.find((a: { detail?: string }) => a.detail === 'password+recovery-code')).toBeTruthy();
  });
  it('disabling MFA needs password and a valid code; an admin can reset a lost device', async () => {
    const ctx = makeApp();
    const { token, password } = await activeUser(ctx);
    const h = bearer(token);
    const enroll = (await request(ctx.app).post('/api/v1/auth/mfa/enroll').set(h).send({ password })).body;
    await request(ctx.app).post('/api/v1/auth/mfa/confirm').set(h).send({ code: totpAt(enroll.secret, stepOf(ctx.config.now().getTime())) });
    expect((await request(ctx.app).post('/api/v1/auth/mfa/disable').set(h).send({ password, code: '000000' })).status).toBe(401);
    expect((await ctx.as('demo-admin').post('/users/mia/reset-mfa')).body.mfa).toBe(false);
    expect((await login(ctx.app, 'mia', password)).status).toBe(200);                                       // no code needed after reset
  });
  it('config and SSO accounts cannot use API credential management', async () => {
    const ctx = makeApp();
    const tok = (await login(ctx.app, 'ana', 'demo-analyst')).body.token;
    expect((await request(ctx.app).post('/api/v1/auth/password').set(bearer(tok)).send({ currentPassword: 'x', newPassword: GOOD })).body.error).toBe('managed_by_config');
  });
});

describe('retention', () => {
  const day = 86_400_000;
  const T = Date.parse('2025-01-01T00:00:00Z');
  const mkOrg = () => {
    const o = new OrgData();
    const ev = (id: string, ageDays: number) => o.events.set(id, { id, orgId: 'o', timestamp: new Date(T - ageDays * day).toISOString(), source: 's', type: 'login_failed', severity: 'low', attrs: {} } as never);
    ['old-closed', 'old-open', 'old-free', 'new'].forEach((id, i) => ev(id, [200, 200, 200, 1][i]!));
    const inc = (id: string, status: string, ev: string, closedAgeDays?: number) => {
      o.alerts.set('a-' + id, { id: 'a-' + id, eventIds: [ev], incidentId: id } as never);
      o.incidents.set(id, { id, status, eventIds: [ev], updatedAt: new Date(T - 1000).toISOString(), closedAt: closedAgeDays === undefined ? undefined : new Date(T - closedAgeDays * day).toISOString() } as never);
      o.analyses.set('an-' + id, { id: 'an-' + id, incidentId: id } as never);
      o.actions.set('ac-' + id, { id: 'ac-' + id, incidentId: id } as never);
    };
    inc('i-closed', 'resolved', 'old-closed', 200);
    inc('i-open', 'triaging', 'old-open');
    return o;
  };
  const policy = { eventDays: 90, incidentDays: 180 };
  it('dry run reports without deleting', () => {
    const o = mkOrg();
    expect(applyRetention(o, policy, T, true)).toMatchObject({ dryRun: true, events: 2, incidents: 1, alerts: 1, analyses: 1, actions: 1 });
    expect([o.events.size, o.incidents.size]).toEqual([4, 2]);
  });
  it('deletes old closed incidents with their records and unreferenced old events, keeps open-incident evidence', () => {
    const o = mkOrg();
    applyRetention(o, policy, T);
    expect([...o.events.keys()].sort()).toEqual(['new', 'old-open']);
    expect([...o.incidents.keys()]).toEqual(['i-open']);
    expect([[...o.alerts.keys()], [...o.analyses.keys()], [...o.actions.keys()]]).toEqual([['a-i-open'], ['an-i-open'], ['ac-i-open']]);
    expect(o.pendingEventDeletes.sort()).toEqual(['old-closed', 'old-free']);
  });
  it('does not delete a closed incident that is still inside its retention window', () => {
    const o = mkOrg();
    o.incidents.get('i-closed')!.closedAt = new Date(T - 10 * day).toISOString();
    applyRetention(o, policy, T);
    expect(o.incidents.has('i-closed')).toBe(true);
    expect(o.events.has('old-closed')).toBe(true);        // still cited by a kept incident
  });
  it('API: admin-only, requires configuration, defaults to a dry run, and is audited', async () => {
    const off = makeApp();
    expect((await off.as('demo-admin').post('/admin/retention/run', {})).body.error).toBe('not_configured');
    const { createApp } = await import('../src/app.js');
    const { DEMO_KEYS, loadConfig } = await import('../src/config.js');
    const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS, retention: policy, now: () => new Date(T) };
    const { app, store } = createApp({ config });
    const call = (key: string, body: object = {}) => request(app).post('/api/v1/admin/retention/run').set('x-api-key', key).send(body);
    expect((await call('demo-analyst')).status).toBe(403);
    await request(app).post('/api/v1/events').set('x-api-key', 'demo-ingestor').send(Array.from({ length: 6 }, (_, i) => ({ id: `r${i}`, timestamp: new Date(T - 400 * day + i * 1000).toISOString(), source: 's', type: 'login_success', user: 'u' })));
    const dry = await call('demo-admin');
    expect([dry.body.dryRun, dry.body.events]).toEqual([true, 6]);
    expect(store.org('org-acme').events.size).toBe(6);
    const real = await call('demo-admin', { dryRun: false });
    expect(real.body.events).toBe(6);
    expect(store.org('org-acme').events.size).toBe(0);
    const audit = (await request(app).get('/api/v1/audit').set('x-api-key', 'demo-auditor')).body.items;
    expect(audit.filter((a: { action: string; outcome: string }) => a.action === 'retention.run' && a.outcome === 'success')).toHaveLength(2);
  });
});
