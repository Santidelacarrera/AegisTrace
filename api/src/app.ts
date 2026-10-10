import express, { NextFunction, Request, RequestHandler, Response } from 'express';
import { z } from 'zod';
import { appendAudit as appendAuditBase, readAnchor, verifyAudit } from './audit.js';
import { Config, hashKey } from './config.js';
import { LoginThrottle, signToken, verifyPassword, verifyToken } from './auth.js';
import { normalizeEvent, parseCsv } from './normalize.js';
import { runDetection } from './pipeline.js';
import { can, Permission } from './rbac.js';
import { Store } from './store.js';
import { PgPersistence } from './persistence.js';
import { ProviderError } from './llm.js';
import { AnalyticsClient } from './analytics.js';
import { AnalysisProvider, AnalysisValidationError, buildAnalysis, inLabScope, ruleBasedProvider } from './analysis.js';
import {
  ActionType, INCIDENT_STATUSES, Incident, IncidentStatus, Principal, ResponseAction, SEVERITIES, Severity, sevRank,
} from './types.js';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { existsSync } from 'node:fs';

declare module 'express-serve-static-core' {
  interface Request { principal?: Principal }
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

const wrap = (fn: (req: Request, res: Response) => Promise<void> | void): RequestHandler => (req, res, next) => {
  Promise.resolve(fn(req, res)).catch(next);
};

export interface AppOptions { config: Config; store?: Store; provider?: AnalysisProvider; persistence?: PgPersistence; analytics?: AnalyticsClient }

export function createApp({ config, store = new Store(), provider = ruleBasedProvider, persistence, analytics }: AppOptions) {
  const app = express();
  const appendAudit: typeof appendAuditBase = (org, key, at, e) => appendAuditBase(org, key, at, e, config.anchorFile);
  app.disable('x-powered-by');
  const keyIndex = new Map(config.keys.map((k) => [hashKey(k.key), { userId: k.userId, orgId: k.orgId, role: k.role } as Principal]));
  const counters = { requests: 0, denied: 0, eventsIngested: 0, rateLimited: 0 };
  const windows = new Map<string, { start: number; n: number }>();
  const nowIso = () => config.now().toISOString();

  app.use((req, res, next) => {
    const t0 = process.hrtime.bigint();
    counters.requests++;
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.on('finish', () => config.log({ msg: 'request', method: req.method, path: req.path, status: res.statusCode, ms: Number(process.hrtime.bigint() - t0) / 1e6, user: req.principal?.userId, org: req.principal?.orgId }));
    next();
  });

  const here = path.dirname(fileURLToPath(import.meta.url));
  const publicDir = [path.join(here, '..', 'public'), path.join(here, '..', '..', 'public')].find((d) => existsSync(d)) ?? here;
  app.get('/health', (_req, res) => { res.json({ status: 'ok' }); });
  app.get('/metrics', (_req, res) => {
    res.type('text/plain').send(Object.entries(counters).map(([k, v]) => `aegistrace_${k}_total ${v}`).join('\n') + '\n');
  });
  app.use('/ui', express.static(publicDir));

  app.use(express.json({ limit: '512kb' }));
  app.use(express.text({ type: 'text/csv', limit: '1mb' }));

  // --- authentication + rate limiting ---------------------------------------
  const api = express.Router();
  const findUser = (orgId: string, userId: string) => config.users.find((u) => u.orgId === orgId && u.userId === userId);   // live lookup: removing a user revokes their sessions
  const throttle = new LoginThrottle();
  const dummyHash = config.users[0]?.passwordHash;

  api.post('/auth/login', wrap((req, res) => {
    const { orgId, userId, password } = z.object({ orgId: z.string().max(64), userId: z.string().max(64), password: z.string().max(200) }).parse(req.body);
    const id = `${orgId}|${userId}`, now = config.now().getTime();
    const user = findUser(orgId, userId);
    const logFail = (why: string) => { if (user) appendAudit(store.org(orgId), config.auditKey, nowIso(), { orgId, actor: userId, role: user.role, action: 'auth.login', resourceType: 'session', resourceId: userId, outcome: 'denied', detail: why }); };
    if (throttle.locked(id, now)) { logFail('locked out'); throw new HttpError(429, 'locked', 'Too many failed attempts; try again later'); }
    const ok = user ? verifyPassword(password, user.passwordHash) : (dummyHash ? verifyPassword(password, dummyHash) && false : false);   // constant-ish work for unknown users
    if (!user || !ok) { throttle.fail(id, now); logFail('bad credentials'); counters.denied++; throw new HttpError(401, 'invalid_credentials', 'Invalid credentials'); }
    throttle.reset(id);
    appendAudit(store.org(orgId), config.auditKey, nowIso(), { orgId, actor: userId, role: user.role, action: 'auth.login', resourceType: 'session', resourceId: userId, outcome: 'success' });
    const finish = () => res.json({ token: signToken(user, config.sessionKey, config.tokenTtlSec, now), expiresInSec: config.tokenTtlSec, user: { userId, orgId, role: user.role } });
    if (persistence) persistence.flush(store, orgId).then(finish, () => res.status(500).json({ error: 'persistence_failed' })); else finish();
  }));

  api.use((req, res, next) => {
    const key = req.header('x-api-key');
    const bearer = req.header('authorization')?.match(/^Bearer (.+)$/i)?.[1];
    let principal: Principal | undefined;
    let limitId = '';
    if (bearer) {
      const t = verifyToken(bearer, config.sessionKey, config.now().getTime());
      const u = t && findUser(t.org, t.sub);
      if (u) principal = { userId: u.userId, orgId: u.orgId, role: u.role };
      limitId = hashKey(bearer);
    } else if (key) { principal = keyIndex.get(hashKey(key)); limitId = hashKey(key); }
    if (!principal) { counters.denied++; return next(new HttpError(401, 'unauthenticated', 'Missing or invalid credentials')); }
    req.principal = principal;
    const id = limitId;
    const now = config.now().getTime();
    const w = windows.get(id);
    if (!w || now - w.start >= 60_000) windows.set(id, { start: now, n: 1 });
    else if (++w.n > config.rateLimitPerMinute) { counters.rateLimited++; res.setHeader('Retry-After', '60'); return next(new HttpError(429, 'rate_limited', 'Too many requests')); }
    next();
  });

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
    const det = accepted ? runDetection(data, p.orgId, nowIso(), extra) : { newAlerts: 0, updatedAlerts: 0 };
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

  return { app, store };
}
