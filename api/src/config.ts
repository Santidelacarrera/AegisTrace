import { createHash } from 'node:crypto';
import { Principal } from './types.js';
import { hashPassword, UserEntry } from './auth.js';
import { RuleContext } from './rules.js';
import { OidcConfig, oidcConfigFromEnv } from './oidc.js';

export interface KeyEntry extends Principal { key: string }

export interface Config {
  keys: KeyEntry[];
  users: UserEntry[];
  sessionKey: string;
  dataKey: string;
  tokenTtlSec: number;
  anchorFile?: string;
  retention?: { eventDays: number; incidentDays: number };
  rules: RuleContext;
  hsts: boolean;
  trustProxy: boolean;
  oidc?: OidcConfig;
  ssoTokenTtlSec: number;
  auditKey: string;
  rateLimitPerMinute: number;
  maxBatch: number;
  now: () => Date;
  log: (entry: Record<string, unknown>) => void;
}

/** Synthetic demo credentials. Refused in production: real deployments must set AEGIS_API_KEYS. */
export const DEMO_KEYS: KeyEntry[] = [
  { key: 'demo-viewer', userId: 'vera', orgId: 'org-acme', role: 'viewer' },
  { key: 'demo-ingestor', userId: 'svc-collector', orgId: 'org-acme', role: 'ingestor' },
  { key: 'demo-analyst', userId: 'ana', orgId: 'org-acme', role: 'analyst' },
  { key: 'demo-approver', userId: 'alex', orgId: 'org-acme', role: 'approver' },
  { key: 'demo-auditor', userId: 'aude', orgId: 'org-acme', role: 'auditor' },
  { key: 'demo-admin', userId: 'root-admin', orgId: 'org-acme', role: 'admin' },
  { key: 'demo-other-admin', userId: 'olivia', orgId: 'org-globex', role: 'admin' },
];

const demoUsers = (): UserEntry[] => DEMO_KEYS.filter((k) => k.key !== 'demo-ingestor').map((k) => ({ userId: k.userId, orgId: k.orgId, role: k.role, passwordHash: hashPassword('demo-' + k.role) }));

const csv = (v?: string) => (v ?? '').split(',').map((x) => x.trim()).filter(Boolean);

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const prod = env.NODE_ENV === 'production';
  let keys: KeyEntry[];
  if (env.AEGIS_API_KEYS) keys = JSON.parse(env.AEGIS_API_KEYS) as KeyEntry[];
  else if (prod) throw new Error('AEGIS_API_KEYS is required when NODE_ENV=production');
  else keys = DEMO_KEYS;
  let users: UserEntry[];
  if (env.AEGIS_USERS) users = JSON.parse(env.AEGIS_USERS) as UserEntry[];
  else users = prod ? [] : demoUsers();
  const sessionKey = env.AEGIS_SESSION_KEY ?? (prod ? '' : 'dev-only-session-key');
  if (!sessionKey) throw new Error('AEGIS_SESSION_KEY is required when NODE_ENV=production');
  const dataKey = env.AEGIS_DATA_KEY ?? (prod ? '' : 'dev-only-data-key');
  if (!dataKey) throw new Error('AEGIS_DATA_KEY is required when NODE_ENV=production');
  const auditKey = env.AEGIS_AUDIT_KEY ?? (prod ? '' : 'dev-only-audit-key');
  if (!auditKey) throw new Error('AEGIS_AUDIT_KEY is required when NODE_ENV=production');
  return {
    keys, users, sessionKey, dataKey, tokenTtlSec: Number(env.AEGIS_TOKEN_TTL ?? 8 * 3600), anchorFile: env.AEGIS_AUDIT_ANCHOR_FILE, retention: env.AEGIS_RETENTION_DAYS ? { eventDays: Number(env.AEGIS_RETENTION_DAYS), incidentDays: Number(env.AEGIS_INCIDENT_RETENTION_DAYS ?? Number(env.AEGIS_RETENTION_DAYS) * 3) } : undefined, rules: { serviceAccounts: csv(env.AEGIS_SERVICE_ACCOUNTS), changeApprovers: csv(env.AEGIS_CHANGE_APPROVERS) }, hsts: env.AEGIS_HSTS === '1', trustProxy: env.AEGIS_TRUST_PROXY === '1', oidc: oidcConfigFromEnv(env), ssoTokenTtlSec: Number(env.AEGIS_SSO_TOKEN_TTL ?? 3600),
    auditKey,
    rateLimitPerMinute: Number(env.AEGIS_RATE_LIMIT ?? 600),
    maxBatch: Number(env.AEGIS_MAX_BATCH ?? 1000),
    now: () => new Date(),
    log: (e) => { if (env.NODE_ENV !== 'test') process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...e }) + '\n'); },
  };
}

export const hashKey = (k: string) => createHash('sha256').update(k).digest('hex');
