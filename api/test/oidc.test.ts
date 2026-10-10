import { createHash } from 'node:crypto';
import http from 'node:http';
import { AddressInfo } from 'node:net';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { DEMO_KEYS, loadConfig } from '../src/config.js';
import { bruteForceEvents } from './helpers.js';

/** A real HTTP identity provider: discovery, JWKS, authorization-code + PKCE token endpoint. */
let idp: http.Server, issuer = '', privateKey: CryptoKey, otherKey: CryptoKey;
const codes = new Map<string, { challenge: string; nonce: string; claims: Record<string, unknown>; aud: string; signWith: 'good' | 'bad'; exp?: number }>();
let nextClaims: Record<string, unknown> = {}, nextAud = 'aegis-client', nextSign: 'good' | 'bad' = 'good', nextExp = 3600, tamperNonce = false;

beforeAll(async () => {
  const kp = await generateKeyPair('RS256'); privateKey = kp.privateKey as CryptoKey;
  otherKey = (await generateKeyPair('RS256')).privateKey as CryptoKey;
  const jwk = { ...(await exportJWK(kp.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  idp = http.createServer(async (req, res) => {
    const url = new URL(req.url!, issuer);
    const json = (o: unknown) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(o)); };
    if (url.pathname === '/.well-known/openid-configuration') return json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` });
    if (url.pathname === '/jwks') return json({ keys: [jwk] });
    if (url.pathname === '/authorize') {                                  // auto-approve and redirect back like a logged-in IdP session
      const q = url.searchParams, code = 'code-' + codes.size;
      codes.set(code, { challenge: q.get('code_challenge')!, nonce: tamperNonce ? 'wrong' : q.get('nonce')!, claims: nextClaims, aud: nextAud, signWith: nextSign, exp: nextExp });
      res.statusCode = 302; res.setHeader('location', `${q.get('redirect_uri')}?code=${code}&state=${q.get('state')}`); return res.end();
    }
    if (url.pathname === '/token') {
      let body = ''; for await (const c of req) body += c;
      const f = new URLSearchParams(body), c = codes.get(f.get('code')!);
      const pkceOk = c && createHash('sha256').update(f.get('code_verifier') ?? '').digest('base64url') === c.challenge;
      if (!c || !pkceOk || f.get('client_secret') !== 'shh') { res.statusCode = 400; return json({ error: 'invalid_grant' }); }
      codes.delete(f.get('code')!);                                        // codes are single-use
      const jwt = await new SignJWT({ ...c.claims, nonce: c.nonce }).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer(issuer).setAudience(c.aud).setIssuedAt().setExpirationTime(`${c.exp}s`).sign(c.signWith === 'good' ? privateKey : otherKey);
      return json({ id_token: jwt, access_token: 'x', token_type: 'Bearer' });
    }
    res.statusCode = 404; res.end();
  });
  await new Promise<void>((r) => idp.listen(0, '127.0.0.1', r));
  issuer = `http://127.0.0.1:${(idp.address() as AddressInfo).port}`;
});
afterAll(() => { idp.close(); });

const mk = () => {
  const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS, oidc: { issuer, clientId: 'aegis-client', clientSecret: 'shh', redirectUri: 'http://app/api/v1/auth/oidc/callback', orgId: 'org-acme', roleMap: { 'sec-admins': 'admin', 'sec-analysts': 'analyst', 'everyone': 'viewer' } as never } };
  return createApp({ config });
};

/** Drives the browser-less flow: /login -> IdP /authorize -> callback. */
async function sso(app: ReturnType<typeof mk>['app'], claims: Record<string, unknown>, opts: { aud?: string; sign?: 'good' | 'bad'; exp?: number; tamper?: boolean; state?: string } = {}) {
  nextClaims = claims; nextAud = opts.aud ?? 'aegis-client'; nextSign = opts.sign ?? 'good'; nextExp = opts.exp ?? 3600; tamperNonce = !!opts.tamper;
  const login = await request(app).get('/api/v1/auth/oidc/login');
  expect(login.status).toBe(302);
  const authz = await fetch(login.headers.location!, { redirect: 'manual' });
  const back = new URL(authz.headers.get('location')!);
  return request(app).get('/api/v1/auth/oidc/callback').query({ code: back.searchParams.get('code')!, state: opts.state ?? back.searchParams.get('state')! });
}

describe('OIDC single sign-on', () => {
  it('advertises SSO only when configured', async () => {
    expect((await request(mk().app).get('/api/v1/auth/config')).body).toEqual({ password: true, oidc: true });
    const plain = createApp({ config: { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS } }).app;
    expect((await request(plain).get('/api/v1/auth/config')).body.oidc).toBe(false);
    expect((await request(plain).get('/api/v1/auth/oidc/login')).status).toBe(404);
  });
  it('sends PKCE S256, state and nonce to the IdP', async () => {
    const { app } = mk();
    const u = new URL((await request(app).get('/api/v1/auth/oidc/login')).headers.location!);
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('state')!.length).toBeGreaterThan(20);
    expect(u.searchParams.get('nonce')!.length).toBeGreaterThan(20);
    expect(u.searchParams.get('client_id')).toBe('aegis-client');
  });
  it('maps IdP groups to the highest matching role, issues a working session and audits it', async () => {
    const { app } = mk();
    const cb = await sso(app, { sub: 'u-1', email: 'Sam@Example.com', groups: ['everyone', 'sec-analysts', 'sec-admins'] });
    expect(cb.status).toBe(302);
    const token = cb.headers.location!.match(/#token=(.+)$/)![1]!;
    const me = await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${token}`);
    expect(me.body).toEqual({ userId: 'sam@example.com', orgId: 'org-acme', role: 'admin' });
    expect((await request(app).post('/api/v1/events').set('Authorization', `Bearer ${token}`).send(bruteForceEvents())).status).toBe(202);
    const audit = (await request(app).get('/api/v1/audit').set('Authorization', `Bearer ${token}`)).body.items;
    expect(audit.find((a: { action: string; detail?: string }) => a.action === 'auth.login' && a.detail === 'oidc')).toBeTruthy();
  });
  it('refuses users with no mapped role', async () => {
    const r = await sso(mk().app, { sub: 'u-2', email: 'x@example.com', groups: ['unrelated'] });
    expect([r.status, r.body.error]).toEqual([403, 'sso_failed']);
  });
  it.each([
    ['token signed by another key', { sign: 'bad' as const }],
    ['wrong audience', { aud: 'someone-else' }],
    ['expired id_token', { exp: -10 }],
    ['nonce that does not match the request', { tamper: true }],
  ])('rejects %s', async (_n, opts) => {
    const r = await sso(mk().app, { sub: 'u-3', email: 'y@example.com', groups: ['sec-admins'] }, opts);
    expect(r.status).toBe(401);
    expect(r.headers.location).toBeUndefined();
  });
  it('rejects an unknown/forged state and a replayed state', async () => {
    const { app } = mk();
    expect((await sso(app, { sub: 'u', groups: ['sec-admins'] }, { state: 'forged' })).status).toBe(400);
    const login = await request(app).get('/api/v1/auth/oidc/login');
    const authz = await fetch(login.headers.location!, { redirect: 'manual' });
    const back = new URL(authz.headers.get('location')!);
    const q = { code: back.searchParams.get('code')!, state: back.searchParams.get('state')! };
    expect((await request(app).get('/api/v1/auth/oidc/callback').query(q)).status).toBe(302);
    expect((await request(app).get('/api/v1/auth/oidc/callback').query(q)).status).toBe(400);
  });
  it('does not accept a tampered SSO token (role escalation)', async () => {
    const { app } = mk();
    const token = (await sso(app, { sub: 'u-4', email: 'z@example.com', groups: ['everyone'] })).headers.location!.match(/#token=(.+)$/)![1]!;
    const [p, s] = token.split('.');
    const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p!, 'base64url').toString()), role: 'admin' })).toString('base64url');
    expect((await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${forged}.${s}`)).status).toBe(401);
  });
});
