import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

/** AES-256-GCM sealing for secrets that must be recoverable (TOTP seeds). Key = HKDF(AEGIS_DATA_KEY). */
const keyOf = (secret: string) => Buffer.from(hkdfSync('sha256', secret, 'aegistrace', 'data-at-rest-v1', 32));

export function seal(plain: string, secret: string): string {
  const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', keyOf(secret), iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return `enc:v1:${iv.toString('base64url')}:${c.getAuthTag().toString('base64url')}:${ct.toString('base64url')}`;
}

export function open(sealed: string, secret: string): string {
  const [tag, v, iv, auth, ct] = sealed.split(':');
  if (tag !== 'enc' || v !== 'v1' || !iv || !auth || !ct) throw new Error('not a sealed value');
  const d = createDecipheriv('aes-256-gcm', keyOf(secret), Buffer.from(iv, 'base64url'));
  d.setAuthTag(Buffer.from(auth, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8');
}
