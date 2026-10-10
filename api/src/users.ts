import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { Role } from './types.js';

/** A user managed through the API (stored per organization). Users from AEGIS_USERS/demo are "config users" and read-only here. */
export interface UserRecord {
  userId: string; orgId: string; role: Role;
  passwordHash: string;
  totpSecret?: string;          // sealed (enc:v1:...)
  pendingTotpSecret?: string;   // sealed, until confirmed with a valid code
  recoveryHashes: string[];     // sha256 of unused recovery codes
  mustChangePassword: boolean;
  disabled: boolean;
  createdAt: string; passwordChangedAt: string;
}

export const USER_ID = /^[a-z0-9][a-z0-9._@-]{1,63}$/;

/** Length-based policy (NIST 800-63B style): 12+ chars, not the user id, not a trivially repeated pattern. */
export function checkPasswordPolicy(pw: string, userId: string): string | undefined {
  if (pw.length < 12) return 'Password must be at least 12 characters';
  if (pw.length > 200) return 'Password is too long';
  if (pw.toLowerCase().includes(userId.toLowerCase())) return 'Password must not contain the user id';
  if (/^(.)\1+$/.test(pw) || /^(?:0123456789|1234567890|abcdefgh|qwertyuiop)/i.test(pw)) return 'Password is too predictable';
  return undefined;
}

export const tempPassword = () => randomBytes(15).toString('base64url');   // 20 url-safe chars, ~120 bits

const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
const code = () => { const b = randomBytes(10); const s = [...b].map((x) => B32[x % 32]).join(''); return `${s.slice(0, 5)}-${s.slice(5)}`; };

export function newRecoveryCodes(n = 10): { codes: string[]; hashes: string[] } {
  const codes = Array.from({ length: n }, code);
  return { codes, hashes: codes.map(sha) };
}

export const looksLikeRecoveryCode = (c: string) => /^[a-z2-7]{5}-[a-z2-7]{5}$/.test(c);

/** Removes and returns true when `candidate` matches an unused recovery code (constant-time per comparison). */
export function consumeRecoveryCode(rec: Pick<UserRecord, 'recoveryHashes'>, candidate: string): boolean {
  const h = Buffer.from(sha(candidate.toLowerCase()), 'hex');
  const i = rec.recoveryHashes.findIndex((x) => timingSafeEqual(Buffer.from(x, 'hex'), h));
  if (i < 0) return false;
  rec.recoveryHashes.splice(i, 1);
  return true;
}
