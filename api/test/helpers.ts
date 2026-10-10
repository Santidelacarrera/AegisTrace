import request from 'supertest';
import { createApp } from '../src/app.js';
import { DEMO_KEYS, loadConfig } from '../src/config.js';
import { AnalysisProvider } from '../src/analysis.js';

export function makeApp(opts: { provider?: AnalysisProvider; rateLimit?: number } = {}) {
  let t = Date.parse('2024-06-01T12:00:00Z');
  const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS, rateLimitPerMinute: opts.rateLimit ?? 10_000, now: () => new Date((t += 1000)) };
  const { app, store } = createApp({ config, provider: opts.provider });
  const as = (key: string) => ({
    get: (url: string) => request(app).get('/api/v1' + url).set('x-api-key', key),
    post: (url: string, body?: unknown) => request(app).post('/api/v1' + url).set('x-api-key', key).send(body as object),
  });
  return { app, store, as, config };
}

export const iso = (min: number) => new Date(Date.parse('2024-06-01T10:00:00Z') + min * 60_000).toISOString();

/** 6 failures for lab.alice from 203.0.113.9, then a success. */
export function bruteForceEvents(prefix = 'e', withSuccess = true) {
  const evs: Record<string, unknown>[] = Array.from({ length: 6 }, (_, i) => ({ id: `${prefix}${i + 1}`, timestamp: iso(i), source: 'auth-service', type: 'login_failed', user: 'lab.alice', ip: '203.0.113.9' }));
  if (withSuccess) evs.push({ id: `${prefix}7`, timestamp: iso(7), source: 'auth-service', type: 'login_success', user: 'lab.alice', ip: '203.0.113.9' });
  return evs;
}
