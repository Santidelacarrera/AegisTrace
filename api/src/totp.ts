import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = '';
  for (const b of buf) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  let bits = 0, value = 0; const out: number[] = [];
  for (const c of s.toUpperCase().replace(/[=\s]/g, '')) {
    const i = B32.indexOf(c);
    if (i < 0) throw new Error('invalid base32');
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

export const newTotpSecret = () => base32Encode(randomBytes(20));

/** RFC 4226/6238 HOTP over a 30 s time step (HMAC-SHA1, the algorithm authenticator apps use). */
export function totpAt(secret: string, step: number, digits = 6): string {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const o = h[h.length - 1]! & 15;
  const code = ((h[o]! & 0x7f) << 24 | h[o + 1]! << 16 | h[o + 2]! << 8 | h[o + 3]!) % 10 ** digits;
  return String(code).padStart(digits, '0');
}

export const stepOf = (nowMs: number) => Math.floor(nowMs / 30_000);

/** Returns the matched time step (to block replay) or undefined. Accepts ±1 step for clock drift. */
export function verifyTotp(secret: string, code: string, nowMs: number, lastUsedStep = -1): number | undefined {
  if (!/^\d{6}$/.test(code)) return undefined;
  for (const d of [0, -1, 1]) {
    const step = stepOf(nowMs) + d;
    const want = Buffer.from(totpAt(secret, step));
    if (step > lastUsedStep && timingSafeEqual(want, Buffer.from(code))) return step;
  }
  return undefined;
}

export const otpauthUri = (secret: string, account: string, issuer = 'AegisTrace') =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
