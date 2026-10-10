import express, { NextFunction, Request, RequestHandler, Response } from 'express';
import { z } from 'zod';
import { appendAudit as appendAuditBase, readAnchor, verifyAudit } from './audit.js';
import { Config, hashKey } from './config.js';
import { newTotpSecret, otpauthUri, stepOf, verifyTotp } from './totp.js';
import { createOidc, OidcError } from './oidc.js';
import { applyRetention } from './retention.js';
import { Limiter, MemoryLimiter } from './limits.js';
import { Histogram } from './metrics.js';
import { hashPassword, LoginThrottle, signToken, verifyPassword, verifyToken } from './auth.js';
import { open as unseal, seal } from './box.js';
import { checkPasswordPolicy, consumeRecoveryCode, looksLikeRecoveryCode, newRecoveryCodes, tempPassword, USER_ID, UserRecord } from './users.js';
import { normalizeEvent, parseCsv } from './normalize.js';
import { runDetection } from './pipeline.js';
import { can, Permission } from './rbac.js';
import { Store } from './store.js';
import { PgPersistence } from './persistence.js';
import { ProviderError } from './llm.js';
import { AnalyticsClient } from './analytics.js';
import { AnalysisProvider, AnalysisValidationError, buildAnalysis, inLabScope, ruleBasedProvider } from './analysis.js';
import {
  Role,
  ActionType, INCIDENT_STATUSES, Incident, IncidentStatus, Principal, ResponseAction, SEVERITIES, Severity, sevRank,
} from './types.js';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { existsSync } from 'node:fs';

declare module 'express-serve-static-core' {
  interface Request { principal?: Principal; mustChangePassword?: boolean }
}

class HttpError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}

const TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  open: ['triaging', 'false_positive'],
  triaging: ['contained', 'resolved', 'false_positive'],
  contained: ['resolved', 'triaging'],
  resolved: ['triaging'],
  false_positive: ['triaging'],
};

const wrap = (fn: (req: Request, res: Response, next: NextFunction) => Promise<void> | void): RequestHandler => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

export interface AppOptions { config: Config; limiter?: Limiter; fetchImpl?: typeof fetch; store?: Store; provider?: AnalysisProvider; persistence?: PgPersistence; analytics?: AnalyticsClient }

export function createApp({ config, store = new Store(), provider = ruleBasedProvider, persistence, analytics, fetchImpl, limiter = new MemoryLimiter(() => config.now().getTime()) }: AppOptions) {
  const app = express();
  const appendAudit: typeof appendAuditBase = (org, key, at, e) => appendAuditBase(org, key, at, e, config.anchorFile, (err) => { counters.anchorErrors++; config.log({ msg: 'audit_anchor_write_failed', error: String(err) }); });
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', 1);
  const keyIndex = new Map(config.keys.map((k) => [hashKey(k.key), { userId: k.userId, orgId: k.orgId, role: k.role } as Principal]));
  const counters = { requests: 0, denied: 0, eventsIngested: 0, rateLimited: 0, anchorErrors: 0 };
  const nowIso = () => config.now().toISOString();
  const latency = new Histogram([5, 10, 25, 50, 100, 250, 500, 1000, 2500]);

  app.use((req, res, next) => {
    const t0 = process.hrtime.bigint();
    counters.requests++;
    // Correlation id: honour a sane inbound one (from a proxy), otherwise mint one; returned and logged.
    const inbound = req.header('x-request-id');
    const rid = inbound && /^[\w.-]{8,64}$/.test(inbound) ? inbound : randomUUID();
    res.setHeader('X-Request-Id', rid);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    if (config.hsts) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      latency.observe(ms);
      config.log({ msg: 'request', rid, method: req.method, path: req.path, status: res.statusCode, ms, user: req.principal?.userId, org: req.principal?.orgId });
    });
    next();
  });

  const here = path.dirname(fileURLToPath(import.meta.url));
  const publicDir = [path.join(here, '..', 'public'), path.join(here, '..', '..', 'public')].find((d) => existsSync(d)) ?? here;
  app.get('/health', (_req, res) => { res.json({ status: 'ok' }); });
  app.get('/ready', wrap(async (_req, res) => {
    // Ready = dependencies reachable. Liveness (/health) stays dependency-free so orchestrators don't restart on a DB blip.
    const checks: Record<string, string> = {};
    if (persistence) checks.database = (await persistence.ping().then(() => 'ok', () => 'down'));
    const ok = Object.values(checks).every((v) => v === 'ok');
    res.status(ok ? 200 : 503).json({ status: ok ? 'ready' : 'degraded', checks });
  }));
  app.get('/metrics', (req, res) => {
    if (config.metricsToken && req.header('authorization') !== `Bearer ${config.metricsToken}`) return void res.status(401).type('text/plain').send('unauthorized\n');
    const lines = Object.entries(counters).map(([k, v]) => `aegistrace_${k}_total ${v}`);
    res.type('text/plain').send([...lines, ...latency.render('aegistrace_request_duration_ms'), `aegistrace_events_stored ${[...store.all()].reduce((n, o) => n + o.events.size, 0)}`].join('\n') + '\n');
  });
  app.use('/ui', express.static(publicDir));

  app.use(express.json({ limit: '512kb' }));
  app.use(express.text({ type: 'text/csv', limit: '1mb' }));

  // --- authentication + rate limiting ---------------------------------------
  const api = express.Router();
  /** One view over API-managed users (stored per org) and config users (AEGIS_USERS/demo). Lookups are live, so disabling or removing a user revokes sessions. */
  interface Account { userId: string; orgId: string; role: Role; passwordHash: string; totpSecret?: string; mustChangePassword: boolean; changedAtSec: number; source: 'store' | 'config'; rec?: UserRecord }
  const findUser = (orgId: string, userId: string): Account | undefined => {
    const rec = store.has(orgId) ? store.org(orgId).users.get(userId) : undefined;
    if (rec) return rec.disabled ? undefined : { userId, orgId, role: rec.role, passwordHash: rec.passwordHash, totpSecret: rec.totpSecret ? unseal(rec.totpSecret, config.dataKey) : undefined, mustChangePassword: rec.mustChangePassword, changedAtSec: Math.floor(Date.parse(rec.passwordChangedAt) / 1000), source: 'store', rec };
    const c = config.users.find((u) => u.orgId === orgId && u.userId === userId);
    return c && { userId, orgId, role: c.role, passwordHash: c.passwordHash, totpSecret: c.totpSecret, mustChangePassword: false, changedAtSec: 0, source: 'config' };
  };
  const throttle = new LoginThrottle(limiter);
  const dummyHash = config.users[0]?.passwordHash ?? hashPassword('x');

  /** Unauthenticated endpoints cost real work (scrypt, IdP round-trips): cap them per client IP, independently of per-user lockout. */
  const ipLimit = (name: string): RequestHandler => wrap(async (req, _res, next) => {
    if ((await limiter.hit(`ip:${name}:${req.ip}`, 60_000)) > config.loginRatePerMinute) { counters.rateLimited++; return next(new HttpError(429, 'rate_limited', 'Too many requests from this address')); }
    next();
  });

  api.post('/auth/login', ipLimit('login'), wrap(async (req, res) => {
    const { orgId, userId, password, code } = z.object({ orgId: z.string().max(64), userId: z.string().max(64), password: z.string().max(200), code: z.string().max(16).optional() }).parse(req.body);
    const id = `${orgId}|${userId}`, now = config.now().getTime();
    const user = findUser(orgId, userId);
    const logFail = (why: string) => { if (user) appendAudit(store.org(orgId), config.auditKey, nowIso(), { orgId, actor: userId, role: user.role, action: 'auth.login', resourceType: 'session', resourceId: userId, outcome: 'denied', detail: why }); };
    if (await throttle.locked(id)) { logFail('locked out'); throw new HttpError(429, 'locked', 'Too many failed attempts; try again later'); }
    const ok = user ? verifyPassword(password, user.passwordHash) : (dummyHash ? verifyPassword(password, dummyHash) && false : false);   // constant-ish work for unknown users
    if (!user || !ok) { await throttle.fail(id); logFail('bad credentials'); counters.denied++; throw new HttpError(401, 'invalid_credentials', 'Invalid credentials'); }
    let mfaUsed = '';
    if (user.totpSecret) {
      // Password was right; now the second factor. A missing code is not counted as a failure (the UI asks for it next).
      if (!code) throw new HttpError(401, 'mfa_required', 'A one-time code is required');
      let used = 'totp';
      if (looksLikeRecoveryCode(code) && user.rec && consumeRecoveryCode(user.rec, code)) used = 'recovery-code';
      else {
        const step = verifyTotp(user.totpSecret, code, now);
        // One use per time step, enforced through the shared limiter so replay is blocked across instances too.
        const replay = step !== undefined && (await limiter.hit(`totp:${id}:${step}`, 120_000)) > 1;
        if (step === undefined || replay) { await throttle.fail(id); logFail(replay ? 'MFA code replay' : 'bad MFA code'); counters.denied++; throw new HttpError(401, 'invalid_credentials', 'Invalid credentials'); }
      }
      mfaUsed = used;
    }
    await throttle.reset(id);
    appendAudit(store.org(orgId), config.auditKey, nowIso(), { orgId, actor: userId, role: user.role, action: 'auth.login', resourceType: 'session', resourceId: userId, outcome: 'success', detail: mfaUsed ? `password+${mfaUsed}` : 'password' });
    const finish = () => res.json({ token: signToken(user, config.sessionKey, config.tokenTtlSec, now, false, user.mustChangePassword), expiresInSec: config.tokenTtlSec, user: { userId, orgId, role: user.role }, mustChangePassword: user.mustChangePassword });
    if (persistence) persistence.flush(store, orgId).then(finish, () => res.status(500).json({ error: 'persistence_failed' })); else finish();
  }));

  // --- SSO (OIDC) -------------------------------------------------------------
  const oidc = config.oidc ? createOidc(config.oidc, () => config.now().getTime(), fetchImpl) : undefined;
  api.get('/auth/config', (_req, res) => { res.json({ password: true, oidc: !!oidc }); });
  api.get('/auth/oidc/login', ipLimit('sso'), wrap(async (_req, res) => {
    if (!oidc) throw new HttpError(404, 'not_found', 'SSO is not configured');
    res.redirect(302, await oidc.start());
  }));
  api.get('/auth/oidc/callback', ipLimit('sso'), wrap(async (req, res) => {
    if (!oidc) throw new HttpError(404, 'not_found', 'SSO is not configured');
    const { code, state } = z.object({ code: z.string().max(2000), state: z.string().max(200) }).parse(req.query);
    const now = config.now().getTime();
    try {
      const u = await oidc.finish(code, state);
      appendAudit(store.org(u.orgId), config.auditKey, nowIso(), { orgId: u.orgId, actor: u.userId, role: u.role, action: 'auth.login', resourceType: 'session', resourceId: u.userId, outcome: 'success', detail: 'oidc' });
      const token = signToken(u, config.sessionKey, config.ssoTokenTtlSec, now, true);
      const done = () => res.redirect(302, `/ui/#token=${token}`);       // fragment: never sent to any server or logged
      if (persistence) persistence.flush(store, u.orgId).then(done, () => res.status(500).json({ error: 'persistence_failed' })); else done();
    } catch (e) {
      // Browser flow: send the person back to the UI with a readable message instead of a JSON error page.
      if (e instanceof OidcError) { counters.denied++; config.log({ msg: 'sso_failed', status: e.status, reason: e.message }); return void res.redirect(302, `/ui/#sso_error=${encodeURIComponent(e.message)}`); }
      throw e;
    }
  }));

  api.use(wrap(async (req, res, next) => {
    const key = req.header('x-api-key');
    const bearer = req.header('authorization')?.match(/^Bearer (.+)$/i)?.[1];
    let principal: Principal | undefined;
    let limitId = '';
    if (bearer) {
      const t = verifyToken(bearer, config.sessionKey, config.now().getTime());
      const u = t && !t.sso && findUser(t.org, t.sub);
      if (u && t && t.iat >= u.changedAtSec) { principal = { userId: u.userId, orgId: u.orgId, role: u.role }; if (t.pwc && u.mustChangePassword) req.mustChangePassword = true; }   // tokens issued before a password change are void
      else if (t?.sso && t.role) principal = { userId: t.sub, orgId: t.org, role: t.role };
      limitId = hashKey(bearer);
    } else if (key) { principal = keyIndex.get(hashKey(key)); limitId = hashKey(key); }
    if (!principal) { counters.denied++; return next(new HttpError(401, 'unauthenticated', 'Missing or invalid credentials')); }
    req.principal = principal;
    if (req.mustChangePassword && !['/auth/password', '/auth/me'].includes(req.path)) return next(new HttpError(403, 'password_change_required', 'You must change your temporary password first'));
    if ((await limiter.hit('rl:' + limitId, 60_000)) > config.rateLimitPerMinute) { counters.rateLimited++; res.setHeader('Retry-After', '60'); return next(new HttpError(429, 'rate_limited', 'Too many requests')); }
    next();
  }));

  // Durability: flush state to PostgreSQL before any mutating response (or audited read) leaves the server.
  if (persistence) {
    api.use((req, res, next) => {
      const send = res.json.bind(res);
      res.json = ((body: unknown) => {
        persistence.flush(store, req.principal!.orgId).then(() => send(body), (err) => { config.log({ msg: 'persist_failed', error: String(err) }); res.status(500); send({ error: 'persistence_failed', message: 'Could not persist state' }); });
        return res;
      }) as typeof res.json;
      next();
    });
  }

  const audit = (req: Request, action: string, resourceType: string, resourceId: string, outcome: 'success' | 'denied' | 'error' = 'success', detail?: string) => {
    const p = req.principal!;
    appendAudit(store.org(p.orgId), config.auditKey, nowIso(), { orgId: p.orgId, actor: p.userId, role: p.role, action, resourceType, resourceId, outcome, detail });
  };

  /** Server-side permission check; denials are audited. */
  const need = (perm: Permission, action: string): RequestHandler => (req, _res, next) => {
    if (can(req.principal!.role, perm)) return next();
    counters.denied++;
    audit(req, action, 'permission', perm, 'denied', `role ${req.principal!.role} lacks ${perm}`);
    next(new HttpError(403, 'forbidden', `Role ${req.principal!.role} lacks ${perm}`));
  };

  const org = (req: Request) => store.org(req.principal!.orgId);
  const incidentOr404 = (req: Request) => {
    const inc = org(req).incidents.get(String(req.params.id));
    if (!inc) throw new HttpError(404, 'not_found', 'Incident not found');
    return inc;
  };
  const touch = (inc: Incident, kind: Incident['activity'][number]['kind'], actor: string, text: string, refs: string[] = []) => {
    const at = nowIso();
    inc.activity.push({ at, kind, actor, text, refs });
    inc.updatedAt = at;
  };

  api.get('/auth/me', (req, res) => {
    const u = findUser(req.principal!.orgId, req.principal!.userId);
    res.json({ ...req.principal, source: u?.source ?? 'sso', mfa: !!u?.totpSecret, mustChangePassword: !!req.mustChangePassword });
  });

  // --- user management (admin) and self-service credentials ----------------------
  const publicUser = (u: UserRecord) => ({ userId: u.userId, role: u.role, disabled: u.disabled, mfa: !!u.totpSecret, mustChangePassword: u.mustChangePassword, createdAt: u.createdAt, source: 'store' as const });
  const activeAdmins = (orgId: string) => new Set([
    ...config.users.filter((u) => u.orgId === orgId && u.role === 'admin').map((u) => u.userId),
    ...[...store.org(orgId).users.values()].filter((u) => u.role === 'admin' && !u.disabled).map((u) => u.userId)]).size;
  const managed = (req: Request) => {
    const u = org(req).users.get(String(req.params.userId));
    if (u) return u;
    if (config.users.some((c) => c.orgId === req.principal!.orgId && c.userId === req.params.userId)) throw new HttpError(409, 'managed_by_config', 'This user is defined in configuration and cannot be changed through the API');
    throw new HttpError(404, 'not_found', 'User not found');
  };
  const markChanged = (u: UserRecord) => { u.passwordChangedAt = nowIso(); };   // voids every earlier session token
  const roleEnum = z.enum(['viewer', 'ingestor', 'analyst', 'approver', 'auditor', 'admin']);

  api.get('/users', need('users:manage', 'user.list'), wrap((req, res) => {
    audit(req, 'user.list', 'user', 'all');
    res.json({ items: [...config.users.filter((u) => u.orgId === req.principal!.orgId).map((u) => ({ userId: u.userId, role: u.role, disabled: false, mfa: !!u.totpSecret, mustChangePassword: false, source: 'config' })), ...[...org(req).users.values()].map(publicUser)] });
  }));

  api.post('/users', need('users:manage', 'user.create'), wrap((req, res) => {
    const b = z.object({ userId: z.string().toLowerCase().regex(USER_ID), role: roleEnum, password: z.string().max(200).optional() }).parse(req.body);
    const data = org(req);
    if (data.users.has(b.userId) || config.users.some((c) => c.orgId === req.principal!.orgId && c.userId === b.userId)) throw new HttpError(409, 'exists', 'User already exists');
    const temp = b.password === undefined;
    const pw = b.password ?? tempPassword();
    const bad = checkPasswordPolicy(pw, b.userId);
    if (bad) throw new HttpError(422, 'weak_password', bad);
    const now = nowIso();
    const rec: UserRecord = { userId: b.userId, orgId: req.principal!.orgId, role: b.role, passwordHash: hashPassword(pw), recoveryHashes: [], mustChangePassword: true, disabled: false, createdAt: now, passwordChangedAt: now };
    data.users.set(rec.userId, rec);
    audit(req, 'user.create', 'user', rec.userId, 'success', `role=${rec.role}`);
    res.status(201).json({ user: publicUser(rec), ...(temp ? { temporaryPassword: pw } : {}) });
  }));

  api.post('/users/:userId/reset-password', need('users:manage', 'user.reset_password'), wrap((req, res) => {
    const u = managed(req);
    const pw = tempPassword();
    u.passwordHash = hashPassword(pw); u.mustChangePassword = true; markChanged(u);
    audit(req, 'user.reset_password', 'user', u.userId);
    res.json({ user: publicUser(u), temporaryPassword: pw });
  }));

  api.post('/users/:userId/reset-mfa', need('users:manage', 'user.reset_mfa'), wrap((req, res) => {
    const u = managed(req);
    u.totpSecret = undefined; u.pendingTotpSecret = undefined; u.recoveryHashes = []; markChanged(u);
    audit(req, 'user.reset_mfa', 'user', u.userId);
    res.json(publicUser(u));
  }));

  api.post('/users/:userId/role', need('users:manage', 'user.role'), wrap((req, res) => {
    const { role } = z.object({ role: roleEnum }).parse(req.body);
    const u = managed(req);
    if (u.userId === req.principal!.userId) throw new HttpError(409, 'self_change', 'You cannot change your own role');
    if (u.role === 'admin' && role !== 'admin' && !u.disabled && activeAdmins(u.orgId) <= 1) throw new HttpError(409, 'last_admin', 'The organization needs at least one active admin');
    audit(req, 'user.role', 'user', u.userId, 'success', `${u.role}->${role}`);
    u.role = role;
    res.json(publicUser(u));
  }));

  for (const [action, disabled] of [['disable', true], ['enable', false]] as const) {
    api.post(`/users/:userId/${action}`, need('users:manage', `user.${action}`), wrap((req, res) => {
      const u = managed(req);
      if (disabled && u.userId === req.principal!.userId) throw new HttpError(409, 'self_change', 'You cannot disable yourself');
      if (disabled && u.role === 'admin' && !u.disabled && activeAdmins(u.orgId) <= 1) throw new HttpError(409, 'last_admin', 'The organization needs at least one active admin');
      u.disabled = disabled;
      if (disabled) markChanged(u);
      audit(req, `user.${action}`, 'user', u.userId);
      res.json(publicUser(u));
    }));
  }

  const self = (req: Request) => {
    const u = org(req).users.get(req.principal!.userId);
    if (!u) throw new HttpError(409, 'managed_by_config', 'Your account is managed outside the API (configuration or SSO)');
    return u;
  };
  const verifyOwn = async (req: Request, u: UserRecord, password: string) => {
    const id = `pwd|${u.orgId}|${u.userId}`;
    if (await throttle.locked(id)) throw new HttpError(429, 'locked', 'Too many failed attempts; try again later');
    if (!verifyPassword(password, u.passwordHash)) { await throttle.fail(id); audit(req, 'auth.verify_password', 'user', u.userId, 'denied'); throw new HttpError(401, 'invalid_credentials', 'Invalid credentials'); }
    await throttle.reset(id);
  };

  api.post('/auth/password', wrap(async (req, res) => {
    const { currentPassword, newPassword } = z.object({ currentPassword: z.string().max(200), newPassword: z.string().max(200) }).parse(req.body);
    const u = self(req);
    await verifyOwn(req, u, currentPassword);
    const bad = checkPasswordPolicy(newPassword, u.userId);
    if (bad) throw new HttpError(422, 'weak_password', bad);
    if (verifyPassword(newPassword, u.passwordHash)) throw new HttpError(422, 'weak_password', 'The new password must be different');
    u.passwordHash = hashPassword(newPassword); u.mustChangePassword = false; markChanged(u);
    audit(req, 'auth.change_password', 'user', u.userId);
    // Other sessions are void now; hand back a fresh token whose iat is after the change.
    res.json({ token: signToken(u, config.sessionKey, config.tokenTtlSec, config.now().getTime() + 1000) });
  }));

  api.post('/auth/mfa/enroll', wrap(async (req, res) => {
    const { password } = z.object({ password: z.string().max(200) }).parse(req.body);
    const u = self(req);
    if (u.totpSecret) throw new HttpError(409, 'mfa_enabled', 'MFA is already enabled');
    await verifyOwn(req, u, password);
    const secret = newTotpSecret();
    u.pendingTotpSecret = seal(secret, config.dataKey);
    audit(req, 'auth.mfa_enroll', 'user', u.userId);
    res.json({ secret, otpauthUri: otpauthUri(secret, `${u.userId}@${u.orgId}`) });
  }));

  api.post('/auth/mfa/confirm', wrap((req, res) => {
    const { code } = z.object({ code: z.string().max(10) }).parse(req.body);
    const u = self(req);
    if (!u.pendingTotpSecret) throw new HttpError(409, 'no_enrollment', 'Start enrollment first');
    const step = verifyTotp(unseal(u.pendingTotpSecret, config.dataKey), code, config.now().getTime());
    if (step === undefined) { audit(req, 'auth.mfa_confirm', 'user', u.userId, 'denied'); throw new HttpError(401, 'invalid_code', 'Invalid code'); }
    const rc = newRecoveryCodes();
    u.totpSecret = u.pendingTotpSecret; u.pendingTotpSecret = undefined; u.recoveryHashes = rc.hashes;
    audit(req, 'auth.mfa_confirm', 'user', u.userId);
    res.json({ recoveryCodes: rc.codes, note: 'Store these now; each works once and they are not shown again.' });
  }));

  api.post('/auth/mfa/disable', wrap(async (req, res) => {
    const { password, code } = z.object({ password: z.string().max(200), code: z.string().max(16) }).parse(req.body);
    const u = self(req);
    if (!u.totpSecret) throw new HttpError(409, 'mfa_disabled', 'MFA is not enabled');
    await verifyOwn(req, u, password);
    const ok = (looksLikeRecoveryCode(code) && consumeRecoveryCode(u, code)) || verifyTotp(unseal(u.totpSecret, config.dataKey), code, config.now().getTime()) !== undefined;
    if (!ok) { audit(req, 'auth.mfa_disable', 'user', u.userId, 'denied'); throw new HttpError(401, 'invalid_code', 'Invalid code'); }
    u.totpSecret = undefined; u.recoveryHashes = [];
    audit(req, 'auth.mfa_disable', 'user', u.userId);
    res.json({ mfa: false });
  }));

  // --- retention ---------------------------------------------------------------------
  const runRetention = (orgId: string, dryRun: boolean) => applyRetention(store.org(orgId), config.retention!, config.now().getTime(), dryRun);
  api.post('/admin/retention/run', need('retention:run', 'retention.run'), wrap((req, res) => {
    if (!config.retention) throw new HttpError(409, 'not_configured', 'Set AEGIS_RETENTION_DAYS to enable retention');
    const { dryRun } = z.object({ dryRun: z.boolean().default(true) }).parse(req.body ?? {});
    const r = runRetention(req.principal!.orgId, dryRun);
    audit(req, 'retention.run', 'organization', req.principal!.orgId, 'success', `${dryRun ? 'dry-run ' : ''}events=${r.events} alerts=${r.alerts} incidents=${r.incidents}`);
    res.json(r);
  }));


  // --- events ---------------------------------------------------------------
  api.post('/events', need('events:write', 'event.ingest'), wrap(async (req, res) => {
    const p = req.principal!;
    let items: unknown[];
    if (typeof req.body === 'string') items = parseCsv(req.body);
    else if (Array.isArray(req.body)) items = req.body;
    else if (req.body && Array.isArray((req.body as { events?: unknown }).events)) items = (req.body as { events: unknown[] }).events;
    else if (req.body && typeof req.body === 'object' && Object.keys(req.body).length) items = [req.body];
    else throw new HttpError(400, 'invalid_body', 'Send an event object, an array, {events: []} or text/csv');
    if (items.length > config.maxBatch) throw new HttpError(413, 'batch_too_large', `At most ${config.maxBatch} events per request`);

    const data = org(req);
    let accepted = 0, duplicates = 0;
    const rejected: { index: number; error: string }[] = [];
    const acceptedIds: string[] = [];
    items.forEach((raw, index) => {
      const r = normalizeEvent(raw, p.orgId);
      if (!r.ok) return void rejected.push({ index, error: r.error });
      if (data.events.has(r.event.id)) return void duplicates++;
      data.events.set(r.event.id, r.event);
      acceptedIds.push(r.event.id);
      accepted++;
    });
    counters.eventsIngested += accepted;
    const extra = accepted && analytics ? await analytics([...data.events.values()]) : [];
    const det = accepted ? runDetection(data, p.orgId, nowIso(), extra, config.rules) : { newAlerts: 0, updatedAlerts: 0 };
    audit(req, 'event.ingest', 'event', `batch:${accepted}`, 'success', `accepted=${accepted} duplicates=${duplicates} rejected=${rejected.length}`);
    res.status(rejected.length && !accepted && !duplicates ? 422 : 202).json({ accepted, duplicates, rejected, acceptedIds, ...det });
  }));

  const page = (q: Request) => {
    const limit = Math.min(Math.max(Number(q.query.limit ?? 50) || 50, 1), 200);
    const offset = Math.max(Number(q.query.offset ?? 0) || 0, 0);
    return { limit, offset };
  };
  const qs = (q: Request, k: string) => (typeof q.query[k] === 'string' ? (q.query[k] as string) : undefined);

  api.get('/events', need('events:read', 'event.search'), wrap((req, res) => {
    const { limit, offset } = page(req);
    const term = qs(req, 'q')?.toLowerCase();
    let list = [...org(req).events.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    for (const f of ['user', 'ip', 'type', 'source', 'resource'] as const) { const v = qs(req, f); if (v) list = list.filter((e) => e[f] === (f === 'user' ? v.toLowerCase() : v)); }
    if (term) list = list.filter((e) => JSON.stringify([e.user, e.ip, e.resource, e.type, e.source, e.attrs]).toLowerCase().includes(term));
    audit(req, 'event.search', 'event', 'query', 'success', `results=${list.length}`);
    res.json({ total: list.length, limit, offset, items: list.slice(offset, offset + limit) });
  }));

  // --- alerts ---------------------------------------------------------------
  api.get('/alerts', need('alerts:read', 'alert.list'), wrap((req, res) => {
    const { limit, offset } = page(req);
    let list = [...org(req).alerts.values()].sort((a, b) => a.firstSeen.localeCompare(b.firstSeen) || a.id.localeCompare(b.id));
    const sev = qs(req, 'severity'), rule = qs(req, 'rule');
    if (sev) list = list.filter((a) => a.severity === sev);
    if (rule) list = list.filter((a) => a.ruleId === rule);
    res.json({ total: list.length, limit, offset, items: list.slice(offset, offset + limit) });
  }));

  // --- incidents --------------------------------------------------------------
  api.get('/incidents', need('incidents:read', 'incident.list'), wrap((req, res) => {
    const { limit, offset } = page(req);
    let list = [...org(req).incidents.values()];
    const status = qs(req, 'status'), sev = qs(req, 'severity'), assignee = qs(req, 'assignee'), label = qs(req, 'label'), term = qs(req, 'q')?.toLowerCase();
    if (status) list = list.filter((i) => i.status === status);
    if (sev) list = list.filter((i) => i.severity === sev);
    if (assignee) list = list.filter((i) => i.assignee === assignee);
    if (label) list = list.filter((i) => i.labels.includes(label));
    if (term) list = list.filter((i) => JSON.stringify([i.title, i.users, i.ips, i.labels]).toLowerCase().includes(term));
    list.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
    res.json({ total: list.length, limit, offset, items: list.slice(offset, offset + limit) });
  }));

  api.get('/incidents/:id', need('incidents:read', 'incident.read'), wrap((req, res) => {
    const inc = incidentOr404(req);
    const data = org(req);
    const events = inc.eventIds.map((id) => data.events.get(id)!).filter(Boolean).sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const timeline = [
      ...events.map((e) => ({ at: e.timestamp, kind: 'event', actor: e.source, text: `${e.type}${e.user ? ' user=' + e.user : ''}${e.ip ? ' ip=' + e.ip : ''}${e.resource ? ' resource=' + e.resource : ''}`, refs: [e.id] })),
      ...inc.activity,
    ].sort((a, b) => a.at.localeCompare(b.at));
    audit(req, 'incident.read', 'incident', inc.id);
    res.json({
      incident: inc, alerts: inc.alertIds.map((id) => data.alerts.get(id)), evidence: events, timeline,
      analyses: [...data.analyses.values()].filter((a) => a.incidentId === inc.id),
      actions: [...data.actions.values()].filter((a) => a.incidentId === inc.id),
    });
  }));

  const statusBody = z.object({ status: z.enum(INCIDENT_STATUSES), reason: z.string().max(500).optional() });
  api.post('/incidents/:id/status', need('incidents:write', 'incident.status'), wrap((req, res) => {
    const body = statusBody.parse(req.body);
    const inc = incidentOr404(req);
    if (!TRANSITIONS[inc.status].includes(body.status)) throw new HttpError(409, 'invalid_transition', `Cannot move from ${inc.status} to ${body.status}`);
    const from = inc.status;
    inc.status = body.status;
    const at = nowIso();
    if (body.status === 'triaging' && !inc.triagedAt) inc.triagedAt = at;
    if (body.status === 'resolved' || body.status === 'false_positive') inc.closedAt = at; else inc.closedAt = undefined;
    touch(inc, 'status', req.principal!.userId, `Status ${from} -> ${body.status}${body.reason ? `: ${body.reason}` : ''}`);
    audit(req, 'incident.status', 'incident', inc.id, 'success', `${from}->${body.status}`);
    res.json(inc);
  }));

  api.post('/incidents/:id/comments', need('incidents:write', 'incident.comment'), wrap((req, res) => {
    const { text } = z.object({ text: z.string().min(1).max(2000) }).parse(req.body);
    const inc = incidentOr404(req);
    touch(inc, 'comment', req.principal!.userId, text);
    audit(req, 'incident.comment', 'incident', inc.id);
    res.status(201).json(inc.activity.at(-1));
  }));

  api.post('/incidents/:id/labels', need('incidents:write', 'incident.label'), wrap((req, res) => {
    const { label } = z.object({ label: z.string().regex(/^[\w:.-]{1,40}$/) }).parse(req.body);
    const inc = incidentOr404(req);
    if (!inc.labels.includes(label)) { inc.labels.push(label); touch(inc, 'label', req.principal!.userId, `Label added: ${label}`); }
    audit(req, 'incident.label', 'incident', inc.id, 'success', label);
    res.json(inc);
  }));

  api.post('/incidents/:id/assignee', need('incidents:write', 'incident.assign'), wrap((req, res) => {
    const { assignee } = z.object({ assignee: z.string().min(1).max(64) }).parse(req.body);
    const inc = incidentOr404(req);
    inc.assignee = assignee;
    touch(inc, 'assignment', req.principal!.userId, `Assigned to ${assignee}`);
    audit(req, 'incident.assign', 'incident', inc.id, 'success', assignee);
    res.json(inc);
  }));

  // --- AI-assisted analysis (recommendations only; never executes) -----------
  api.post('/incidents/:id/analysis', need('analysis:request', 'analysis.request'), wrap(async (req, res) => {
    const inc = incidentOr404(req);
    const data = org(req);
    const events = inc.eventIds.map((id) => data.events.get(id)!).filter(Boolean);
    const alerts = inc.alertIds.map((id) => data.alerts.get(id)!).filter(Boolean);
    try {
      const { analysis, recommendations } = await buildAnalysis(provider, { incident: inc, alerts, events }, req.principal!.userId, nowIso());
      data.analyses.set(analysis.id, analysis);
      recommendations.forEach((r) => data.recommendations.set(r.id, r));
      touch(inc, 'analysis', req.principal!.userId, `Analysis ${analysis.id} generated by ${analysis.provider}`, analysis.summaryEvidenceIds);
      audit(req, 'analysis.request', 'incident', inc.id, 'success', analysis.id);
      res.status(201).json(analysis);
    } catch (e) {
      if (e instanceof AnalysisValidationError) {
        audit(req, 'analysis.request', 'incident', inc.id, 'error', `rejected: ${e.message}`);
        throw new HttpError(502, 'analysis_invalid', `Analysis discarded: ${e.message}`);
      }
      if (e instanceof ProviderError) {
        audit(req, 'analysis.request', 'incident', inc.id, 'error', e.message);
        throw new HttpError(502, 'analysis_unavailable', e.message);
      }
      throw e;
    }
  }));

  // --- response actions -------------------------------------------------------
  const proposeBody = z.object({ recommendationId: z.string().optional(), type: z.enum(['block_ip', 'disable_user']).optional(), target: z.string().max(100).optional() })
    .refine((b) => b.recommendationId || (b.type && b.target), 'Provide recommendationId or type+target');

  api.post('/incidents/:id/actions', need('actions:propose', 'action.propose'), wrap((req, res) => {
    const body = proposeBody.parse(req.body);
    const inc = incidentOr404(req);
    const data = org(req);
    let type: ActionType, target: string;
    if (body.recommendationId) {
      const rec = data.recommendations.get(body.recommendationId);
      if (!rec || rec.incidentId !== inc.id) throw new HttpError(404, 'not_found', 'Recommendation not found for this incident');
      if (rec.kind === 'manual_review') throw new HttpError(422, 'not_executable', 'Manual-review recommendations cannot be turned into actions');
      type = rec.kind; target = rec.target;
    } else { type = body.type!; target = body.target!.toLowerCase(); }
    if (!inLabScope(type, target)) {
      audit(req, 'action.propose', 'incident', inc.id, 'denied', `${type} ${target} outside lab scope`);
      throw new HttpError(422, 'outside_lab_scope', `${target} is outside the lab scope; only simulated actions on lab targets are supported`);
    }
    const action: ResponseAction = {
      id: 'act_' + createHash('sha256').update(`${inc.id}|${type}|${target}|${nowIso()}|${data.actions.size}`).digest('hex').slice(0, 16),
      orgId: req.principal!.orgId, incidentId: inc.id, recommendationId: body.recommendationId, type, target,
      mode: 'simulated', status: 'pending_approval', proposedBy: req.principal!.userId, createdAt: nowIso(),
    };
    data.actions.set(action.id, action);
    touch(inc, 'action', req.principal!.userId, `Proposed ${type} on ${target} (pending approval)`);
    audit(req, 'action.propose', 'action', action.id, 'success', `${type} ${target}`);
    res.status(201).json(action);
  }));

  api.get('/actions', need('actions:read', 'action.list'), wrap((req, res) => {
    const status = qs(req, 'status');
    res.json({ items: [...org(req).actions.values()].filter((a) => !status || a.status === status) });
  }));

  const actionOr404 = (req: Request) => {
    const a = org(req).actions.get(String(req.params.id));
    if (!a) throw new HttpError(404, 'not_found', 'Action not found');
    return a;
  };

  api.post('/actions/:id/approve', need('actions:approve', 'action.approve'), wrap((req, res) => {
    const a = actionOr404(req);
    const p = req.principal!;
    if (a.status !== 'pending_approval') throw new HttpError(409, 'not_pending', `Action is already ${a.status}`);
    if (a.proposedBy === p.userId) {
      audit(req, 'action.approve', 'action', a.id, 'denied', 'proposer cannot approve their own action');
      throw new HttpError(403, 'self_approval', 'Four-eyes rule: the proposer cannot approve their own action');
    }
    const data = org(req);
    // Simulation only: mutates in-memory lab state, never a real system.
    if (a.type === 'block_ip') data.lab.blockedIps.add(a.target); else data.lab.disabledUsers.add(a.target);
    a.status = 'executed'; a.decidedBy = p.userId; a.decidedAt = nowIso();
    a.result = `SIMULATED: ${a.type === 'block_ip' ? 'blocked IP' : 'disabled user'} ${a.target} in lab state; no real system was changed`;
    audit(req, 'action.approve', 'action', a.id, 'success', `${a.type} ${a.target}`);
    audit(req, 'action.execute', 'action', a.id, 'success', a.result);
    const inc = data.incidents.get(a.incidentId);
    if (inc) touch(inc, 'action', p.userId, `Approved and executed (simulated) ${a.type} on ${a.target}`);
    res.json(a);
  }));

  api.post('/actions/:id/reject', need('actions:approve', 'action.reject'), wrap((req, res) => {
    const a = actionOr404(req);
    if (a.status !== 'pending_approval') throw new HttpError(409, 'not_pending', `Action is already ${a.status}`);
    a.status = 'rejected'; a.decidedBy = req.principal!.userId; a.decidedAt = nowIso();
    audit(req, 'action.reject', 'action', a.id, 'success');
    const inc = org(req).incidents.get(a.incidentId);
    if (inc) touch(inc, 'action', req.principal!.userId, `Rejected ${a.type} on ${a.target}`);
    res.json(a);
  }));

  api.get('/lab-state', need('actions:read', 'lab.read'), (req, res) => {
    const lab = org(req).lab;
    res.json({ blockedIps: [...lab.blockedIps], disabledUsers: [...lab.disabledUsers], simulated: true });
  });

  // --- audit ------------------------------------------------------------------
  api.get('/audit', need('audit:read', 'audit.read'), wrap((req, res) => {
    const { limit, offset } = page(req);
    const entries = org(req).audit;
    res.json({ total: entries.length, limit, offset, items: entries.slice(offset, offset + limit) });
  }));
  api.get('/audit/verify', need('audit:read', 'audit.verify'), wrap((req, res) => {
    const head = qs(req, 'anchorHead'), n = Number(qs(req, 'anchorEntries'));
    const anchor = head && Number.isInteger(n) ? { head, entries: n } : config.anchorFile ? readAnchor(config.anchorFile, req.principal!.orgId) : undefined;
    res.json(verifyAudit(org(req), config.auditKey, anchor));
  }));

  // --- dashboard ----------------------------------------------------------------
  api.get('/dashboard', need('dashboard:read', 'dashboard.read'), wrap((req, res) => {
    const data = org(req);
    const alertsBySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    data.alerts.forEach((a) => alertsBySeverity[a.severity]++);
    const incidents = [...data.incidents.values()];
    const closed = incidents.filter((i) => i.status === 'resolved' || i.status === 'false_positive');
    const triage = incidents.filter((i) => i.triagedAt).map((i) => (Date.parse(i.triagedAt!) - Date.parse(i.createdAt)) / 60000).sort((a, b) => a - b);
    const median = triage.length ? (triage[Math.floor((triage.length - 1) / 2)]! + triage[Math.ceil((triage.length - 1) / 2)]!) / 2 : null;
    res.json({
      events: data.events.size, alerts: data.alerts.size, alertsBySeverity,
      openIncidents: incidents.filter((i) => i.status !== 'resolved' && i.status !== 'false_positive').length,
      incidentsByStatus: Object.fromEntries(INCIDENT_STATUSES.map((s) => [s, incidents.filter((i) => i.status === s).length])),
      medianTriageMinutes: median,
      falsePositiveRate: closed.length ? closed.filter((i) => i.status === 'false_positive').length / closed.length : null,
      pendingActions: [...data.actions.values()].filter((a) => a.status === 'pending_approval').length,
    });
  }));

  app.use('/api/v1', api);

  app.use((_req, _res, next) => next(new HttpError(404, 'not_found', 'Route not found')));
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof HttpError) return void res.status(err.status).json({ error: err.code, message: err.message });
    if (err instanceof z.ZodError) return void res.status(400).json({ error: 'invalid_request', message: 'Validation failed', issues: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })) });
    const e = err as { type?: string; status?: number };
    if (e.type === 'entity.too.large') return void res.status(413).json({ error: 'payload_too_large', message: 'Request body too large' });
    if (e.type === 'entity.parse.failed') return void res.status(400).json({ error: 'invalid_json', message: 'Malformed JSON' });
    config.log({ msg: 'unhandled_error', error: String((err as Error)?.stack ?? err), path: req.path });
    res.status(500).json({ error: 'internal', message: 'Internal error' });
  });

  // Scheduled retention (every org), if configured. unref'd so it never keeps the process alive; the caller owns shutdown.
  const retentionTimer = config.retention ? setInterval(() => {
    for (const orgId of store.ids()) {
      const r = runRetention(orgId, false);
      if (r.events + r.alerts + r.incidents > 0) {
        config.log({ msg: 'retention', orgId, ...r });
        appendAudit(store.org(orgId), config.auditKey, nowIso(), { orgId, actor: 'system', role: 'system', action: 'retention.run', resourceType: 'organization', resourceId: orgId, outcome: 'success', detail: `scheduled events=${r.events} alerts=${r.alerts} incidents=${r.incidents}` });
        persistence?.flush(store, orgId).catch((e) => config.log({ msg: 'persist_failed', error: String(e) }));
      }
    }
  }, 6 * 3600_000) : undefined;
  retentionTimer?.unref();

  return { app, store };
}
