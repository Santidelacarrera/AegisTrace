import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { NormEvent, Severity, SEVERITIES } from './types.js';

const TYPE_ALIASES: Record<string, string> = {
  login_failed: 'login_failed', failed_login: 'login_failed', login_failure: 'login_failed',
  auth_failure: 'login_failed', authentication_failed: 'login_failed', invalid_password: 'login_failed',
  login_success: 'login_success', login: 'login_success', auth_success: 'login_success',
  authentication_succeeded: 'login_success', successful_login: 'login_success',
  authz_denied: 'authz_denied', access_denied: 'authz_denied', forbidden: 'authz_denied',
  authorization_failed: 'authz_denied', permission_denied: 'authz_denied', http_403: 'authz_denied',
  permission_change: 'permission_change', role_change: 'permission_change', permission_granted: 'permission_change',
  iam_policy_change: 'permission_change', role_assigned: 'permission_change',
};

const DEFAULT_SEVERITY: Record<string, Severity> = {
  login_failed: 'low', login_success: 'info', authz_denied: 'low', permission_change: 'medium',
};

const FIELD_ALIASES: Record<string, string[]> = {
  timestamp: ['timestamp', 'time', 'ts', '@timestamp', 'date'],
  source: ['source', 'service', 'system'],
  type: ['type', 'event_type', 'event', 'action'],
  user: ['user', 'username', 'account', 'user_id'],
  ip: ['ip', 'src_ip', 'source_ip', 'client_ip', 'remote_addr'],
  resource: ['resource', 'asset', 'host', 'target', 'path'],
  severity: ['severity', 'level'],
  message: ['message', 'msg', 'description'],
  actor: ['actor', 'performed_by'],
  new_role: ['new_role', 'role'],
  old_role: ['old_role', 'previous_role'],
  status_code: ['status_code', 'status'],
  id: ['id', 'event_id'],
};

const MAX_FIELD = 256;
const MAX_MESSAGE = 512;

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000B-\u001F\u007F]/g;
const clean = (v: unknown, max = MAX_FIELD): string => String(v).replace(CONTROL, '').trim().slice(0, max);

function pick(raw: Record<string, unknown>, field: string): string | undefined {
  for (const k of FIELD_ALIASES[field] ?? [field]) {
    const v = raw[k];
    if (v !== undefined && v !== null && String(v).trim() !== '') return clean(v, field === 'message' ? MAX_MESSAGE : MAX_FIELD);
  }
  return undefined;
}

function parseTime(v: string): string | undefined {
  let d: Date;
  if (/^\d{9,13}$/.test(v)) d = new Date(v.length <= 10 ? Number(v) * 1000 : Number(v));
  else if (/^\d{4}-\d{2}-\d{2}/.test(v)) d = new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(v) ? v : v + 'Z');
  else return undefined;
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

export type NormResult = { ok: true; event: NormEvent } | { ok: false; error: string };

export function normalizeEvent(rawIn: unknown, orgId: string): NormResult {
  if (typeof rawIn !== 'object' || rawIn === null || Array.isArray(rawIn)) return { ok: false, error: 'event must be an object' };
  const raw = rawIn as Record<string, unknown>;

  const tsRaw = pick(raw, 'timestamp');
  if (!tsRaw) return { ok: false, error: 'timestamp is required' };
  const timestamp = parseTime(tsRaw);
  if (!timestamp) return { ok: false, error: 'timestamp is not a valid date' };

  const source = pick(raw, 'source');
  if (!source) return { ok: false, error: 'source is required' };

  const typeRaw = pick(raw, 'type');
  if (!typeRaw) return { ok: false, error: 'type is required' };
  const typeKey = typeRaw.toLowerCase().replace(/[\s.\-/]+/g, '_');
  const type = TYPE_ALIASES[typeKey] ?? typeKey.replace(/[^a-z0-9_]/g, '').slice(0, 64);
  if (!type) return { ok: false, error: 'type is invalid' };

  const ipRaw = pick(raw, 'ip');
  if (ipRaw && !isIP(ipRaw)) return { ok: false, error: 'ip is not a valid IPv4/IPv6 address' };

  const sevRaw = pick(raw, 'severity')?.toLowerCase();
  if (sevRaw && !(SEVERITIES as readonly string[]).includes(sevRaw)) return { ok: false, error: `severity must be one of ${SEVERITIES.join(', ')}` };
  const severity = (sevRaw as Severity | undefined) ?? DEFAULT_SEVERITY[type] ?? 'info';

  const attrs: Record<string, string> = {};
  for (const f of ['message', 'actor', 'new_role', 'old_role', 'status_code']) {
    const v = pick(raw, f);
    if (v !== undefined) attrs[f] = v;
  }
  const user = pick(raw, 'user')?.toLowerCase();
  const resource = pick(raw, 'resource');
  const ip = ipRaw;

  const idRaw = pick(raw, 'id');
  const id =
    idRaw && /^[\w.:-]{1,64}$/.test(idRaw)
      ? idRaw
      : 'evt_' + createHash('sha256').update(JSON.stringify([timestamp, source, type, user, ip, resource, attrs])).digest('hex').slice(0, 16);

  const event: NormEvent = { id, orgId, timestamp, source: source.toLowerCase(), type, severity, attrs };
  if (user) event.user = user;
  if (ip) event.ip = ip;
  if (resource) event.resource = resource;
  return { ok: true, event };
}

/** Minimal RFC-4180 CSV parser (quotes, escaped quotes, CRLF). Returns objects keyed by header. */
export function parseCsv(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let row: string[] = [], field = '', inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some((x) => x !== '')) rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some((x) => x !== '')) rows.push(row);
  const [header, ...body] = rows;
  if (!header) return [];
  const keys = header.map((h) => h.trim());
  return body.map((r) => Object.fromEntries(keys.map((k, i) => [k, r[i] ?? ''])));
}
