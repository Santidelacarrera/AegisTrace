import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { Principal, Role } from './types.js';

export interface UserEntry extends Principal { passwordHash: string }

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  return `scrypt$${salt.toString('base64url')}$${scryptSync(password, salt, 32).toString('base64url')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [alg, salt, hash] = stored.split('$');
  if (alg !== 'scrypt' || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64url');
  const actual = scryptSync(password, Buffer.from(salt, 'base64url'), expected.length);
  return timingSafeEqual(actual, expected);
}

/** Compact signed session token: base64url(payload).base64url(HMAC-SHA256). Stateless; revocation = removing the user. */
export function signToken(p: Principal, key: string, ttlSec: number, nowMs: number): string {
  const payload = Buffer.from(JSON.stringify({ sub: p.userId, org: p.orgId, exp: Math.floor(nowMs / 1000) + ttlSec })).toString('base64url');
  return `${payload}.${createHmac('sha256', key).update(payload).digest('base64url')}`;
}

export function verifyToken(token: string, key: string, nowMs: number): { sub: string; org: string } | undefined {
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return undefined;
  const good = createHmac('sha256', key).update(payload).digest();
  const given = Buffer.from(sig, 'base64url');
  if (given.length !== good.length || !timingSafeEqual(given, good)) return undefined;
  try {
    const body = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (typeof body.exp !== 'number' || body.exp * 1000 < nowMs) return undefined;
    return { sub: String(body.sub), org: String(body.org) };
  } catch { return undefined; }
}

export const ROLES: readonly Role[] = ['viewer', 'ingestor', 'analyst', 'approver', 'auditor', 'admin'];

/** Failed-login throttling: 5 failures per (org,user) within 15 minutes locks further attempts until the window ends. */
export class LoginThrottle {
  private fails = new Map<string, number[]>();
  constructor(private max = 5, private windowMs = 15 * 60_000) {}
  locked(id: string, now: number) { return this.recent(id, now).length >= this.max; }
  fail(id: string, now: number) { this.fails.set(id, [...this.recent(id, now), now]); }
  reset(id: string) { this.fails.delete(id); }
  private recent(id: string, now: number) { return (this.fails.get(id) ?? []).filter((t) => now - t < this.windowMs); }
}
