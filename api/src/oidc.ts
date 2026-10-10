import { createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { Role } from './types.js';

export interface OidcConfig {
  issuer: string; clientId: string; clientSecret: string; redirectUri: string;
  orgId: string;
  /** IdP group/role value -> AegisTrace role. Users matching none are refused (no default role). */
  roleMap: Record<string, Role>;
  groupsClaim?: string;
  scopes?: string;
}

export class OidcError extends Error { constructor(public status: number, message: string) { super(message); } }

const PRECEDENCE: Role[] = ['admin', 'approver', 'analyst', 'auditor', 'ingestor', 'viewer'];
const b64u = (b: Buffer) => b.toString('base64url');

export function oidcConfigFromEnv(env: NodeJS.ProcessEnv): OidcConfig | undefined {
  if (!env.OIDC_ISSUER) return undefined;
  for (const k of ['OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_REDIRECT_URI', 'OIDC_ORG_ID', 'OIDC_ROLE_MAP'])
    if (!env[k]) throw new Error(`${k} is required when OIDC_ISSUER is set`);
  return { issuer: env.OIDC_ISSUER, clientId: env.OIDC_CLIENT_ID!, clientSecret: env.OIDC_CLIENT_SECRET!, redirectUri: env.OIDC_REDIRECT_URI!, orgId: env.OIDC_ORG_ID!, roleMap: JSON.parse(env.OIDC_ROLE_MAP!), groupsClaim: env.OIDC_GROUPS_CLAIM };
}

/**
 * OpenID Connect authorization-code flow with PKCE (S256), state and nonce.
 * The id_token signature, issuer, audience, expiry and nonce are all verified against the IdP's JWKS.
 */
export function createOidc(cfg: OidcConfig, now: () => number = Date.now, fetchImpl: typeof fetch = fetch) {
  type Meta = { authorization_endpoint: string; token_endpoint: string; jwks_uri: string; issuer: string };
  let meta: Meta | undefined;
  let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;
  const pending = new Map<string, { verifier: string; nonce: string; exp: number }>();

  async function discover() {
    if (meta) return meta;
    const res = await fetchImpl(`${cfg.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`);
    if (!res.ok) throw new OidcError(502, 'IdP discovery failed');
    const m = (await res.json()) as Meta | null;
    if (!m || m.issuer !== cfg.issuer) throw new OidcError(502, 'IdP issuer mismatch');
    jwks = createRemoteJWKSet(new URL(m.jwks_uri));
    meta = m;
    return m;
  }

  return {
    async start(): Promise<string> {
      const m = await discover();
      for (const [k, v] of pending) if (v.exp < now()) pending.delete(k);
      if (pending.size > 1000) throw new OidcError(429, 'Too many pending logins');
      const state = b64u(randomBytes(24)), nonce = b64u(randomBytes(24)), verifier = b64u(randomBytes(48));
      pending.set(state, { verifier, nonce, exp: now() + 10 * 60_000 });
      const u = new URL(m.authorization_endpoint);
      u.search = new URLSearchParams({
        response_type: 'code', client_id: cfg.clientId, redirect_uri: cfg.redirectUri, scope: cfg.scopes ?? 'openid email profile groups',
        state, nonce, code_challenge: b64u(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256',
      }).toString();
      return u.toString();
    },

    async finish(code: string, state: string): Promise<{ userId: string; orgId: string; role: Role }> {
      const p = pending.get(state);
      pending.delete(state);                                   // single use
      if (!p || p.exp < now()) throw new OidcError(400, 'Invalid or expired login state');
      const m = await discover();
      const res = await fetchImpl(m.token_endpoint, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: cfg.redirectUri, client_id: cfg.clientId, client_secret: cfg.clientSecret, code_verifier: p.verifier }),
      });
      if (!res.ok) throw new OidcError(401, 'Code exchange failed');
      const { id_token } = (await res.json()) as { id_token?: string };
      if (!id_token) throw new OidcError(401, 'IdP returned no id_token');
      let claims: Record<string, unknown>;
      try {
        ({ payload: claims } = await jwtVerify(id_token, jwks!, { issuer: cfg.issuer, audience: cfg.clientId, currentDate: new Date(now()) }));
      } catch { throw new OidcError(401, 'Invalid id_token'); }
      if (claims.nonce !== p.nonce) throw new OidcError(401, 'Nonce mismatch');
      const raw = claims[cfg.groupsClaim ?? 'groups'];
      const groups = Array.isArray(raw) ? raw.map(String) : typeof raw === 'string' ? [raw] : [];
      const roles = groups.map((g) => cfg.roleMap[g]).filter((r): r is Role => !!r);
      const role = PRECEDENCE.find((r) => roles.includes(r));
      if (!role) throw new OidcError(403, 'Your account has no AegisTrace role');
      const id = String(claims.email ?? claims.sub ?? '').toLowerCase();
      if (!id || typeof claims.sub !== 'string') throw new OidcError(401, 'id_token has no subject');
      return { userId: id.slice(0, 64), orgId: cfg.orgId, role };
    },
  };
}
