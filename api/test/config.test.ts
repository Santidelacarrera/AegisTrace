import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';

describe('config', () => {
  it('refuses demo credentials in production', () => {
    expect(() => loadConfig({ NODE_ENV: 'production' } as NodeJS.ProcessEnv)).toThrow(/AEGIS_API_KEYS/);
    expect(() => loadConfig({ NODE_ENV: 'production', AEGIS_API_KEYS: '[]', AEGIS_SESSION_KEY: 's' } as NodeJS.ProcessEnv)).toThrow(/AEGIS_AUDIT_KEY/);
  });
  it('accepts explicit keys in production', () => {
    const c = loadConfig({ NODE_ENV: 'production', AEGIS_API_KEYS: '[{"key":"k","userId":"u","orgId":"o","role":"viewer"}]', AEGIS_AUDIT_KEY: 's3cret', AEGIS_SESSION_KEY: 's' } as NodeJS.ProcessEnv);
    expect(c.keys).toHaveLength(1);
  });
});
