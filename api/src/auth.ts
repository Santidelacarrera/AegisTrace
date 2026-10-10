import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { Limiter } from './limits.js';
import { Principal, Role } from './types.js';

export interface UserEntry extends Principal { passwordHash: string; /** base32 TOTP secret; when set, login also requires a valid code */ totpSecret?: string }

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  // ':' separators, not '$': hashes get pasted into .env files, where docker compose would interpolate '$salt'.
  return `scrypt:${salt.toString('base64url')}:${scryptSync(password, salt, 32).toString('base64url')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [alg, salt, hash] = stored.split(/[$:]/);   // legacy 'scrypt$salt$hash' still verifies
  if (alg !== 'scrypt' || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64url');
  const actual = scryptSync(password, Buffer.from(salt, 'base64url'), expected.length);
  return timingSafeEqual(actual, expected);
}

/** Compact signed session token: base64url(payload).base64url(HMAC-SHA256). Stateless; revocation = removing the user. */
export function signToken(p: Principal, key: string, ttlSec: number, nowMs: number, sso = false, mustChangePassword = false): string {
  // SSO tokens carry the role (the IdP is the source of truth, there is no local user row to look up), so keep their TTL short.
  const payload = Buffer.from(JSON.stringify({ sub: p.userId, org: p.orgId, iat: Math.floor(nowMs / 1000), exp: Math.floor(nowMs / 1000) + ttlSec, ...(sso ? { sso: 1, role: p.role } : {}), ...(mustChangePassword ? { pwc: 1 } : {}) })).toString('base64url');
  return `${payload}.${createHmac('sha256', key).update(payload).digest('base64url')}`;
}

export function verifyToken(token: string, key: string, nowMs: number): { sub: string; org: string; iat: number; sso?: boolean; role?: Role; pwc?: boolean } | undefined {
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return undefined;
  const good = createHmac('sha256', key).update(payload).digest();
  const given = Buffer.from(sig, 'base64url');
  if (given.length !== good.length || !timingSafeEqual(given, good)) return undefined;
  try {
    const body = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (typeof body.exp !== 'number' || body.exp * 1000 < nowMs) return undefined;
    return { sub: String(body.sub), org: String(body.org), iat: Number(body.iat ?? 0), ...(body.sso ? { sso: true, role: body.role as Role } : {}), ...(body.pwc ? { pwc: true } : {}) };
  } catch { return undefined; }
}

export const ROLES: readonly Role[] = ['viewer', 'ingestor', 'analyst', 'approver', 'auditor', 'admin'];

/** Failed-login throttling: `max` failures per (org,user) within the window lock further attempts until it ends. */
export class LoginThrottle {
  constructor(private limiter: Limiter, private max = 5, private windowMs = 15 * 60_000) {}
  async locked(id: string) { return (await this.limiter.peek('login:' + id)) >= this.max; }
  async fail(id: string) { await this.limiter.hit('login:' + id, this.windowMs); }
  async reset(id: string) { await this.limiter.reset('login:' + id); }
}
