import { createClient } from 'redis';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApp } from '../src/app.js';
import { DEMO_KEYS, loadConfig } from '../src/config.js';
import { MemoryLimiter, RedisLimiter } from '../src/limits.js';

describe('MemoryLimiter', () => {
  it('counts within a window and restarts after it', async () => {
    let t = 0; const l = new MemoryLimiter(() => t);
    expect([await l.hit('k', 1000), await l.hit('k', 1000), await l.peek('k')]).toEqual([1, 2, 2]);
    t = 1000; expect(await l.hit('k', 1000)).toBe(1);
    await l.reset('k'); expect(await l.peek('k')).toBe(0);
  });
});

describe.skipIf(!process.env.TEST_REDIS_URL)('RedisLimiter (real Redis, set TEST_REDIS_URL)', () => {
  const client = createClient({ url: process.env.TEST_REDIS_URL });
  beforeAll(async () => { await client.connect(); await client.flushDb(); });
  afterAll(async () => { await client.quit(); });

  const instance = (limit: number) => {
    const config = { ...loadConfig({ NODE_ENV: 'test' } as NodeJS.ProcessEnv), keys: DEMO_KEYS, rateLimitPerMinute: limit };
    return createApp({ config, limiter: new RedisLimiter(client as never, new MemoryLimiter()) }).app;
  };
  const get = (app: ReturnType<typeof instance>, key: string) => request(app).get('/api/v1/alerts').set('x-api-key', key);

  it('expires counters', async () => {
    const l = new RedisLimiter(client as never, new MemoryLimiter());
    expect(await l.hit('exp', 150)).toBe(1);
    await new Promise((r) => setTimeout(r, 250));
    expect(await l.hit('exp', 150)).toBe(1);
  });
  it('shares the request rate limit across API instances', async () => {
    const a = instance(5), b = instance(5);
    const codes: number[] = [];
    for (let i = 0; i < 3; i++) codes.push((await get(a, 'demo-viewer')).status);
    for (let i = 0; i < 3; i++) codes.push((await get(b, 'demo-viewer')).status);
    expect(codes).toEqual([200, 200, 200, 200, 200, 429]);       // the 6th request overall is refused, on the other instance
  });
  it('shares login lockout across instances', async () => {
    const a = instance(1000), b = instance(1000);
    const login = (app: typeof a, password: string) => request(app).post('/api/v1/auth/login').send({ orgId: 'org-acme', userId: 'ana', password });
    for (let i = 0; i < 3; i++) await login(a, 'bad');
    for (let i = 0; i < 2; i++) await login(b, 'bad');
    expect((await login(a, 'demo-analyst')).status).toBe(429);
    expect((await login(b, 'demo-analyst')).status).toBe(429);
  });
  it('falls back to local limits when Redis is down, instead of failing requests', async () => {
    const dead = createClient({ url: 'redis://127.0.0.1:1', socket: { reconnectStrategy: false } });
    dead.on('error', () => undefined);
    const l = new RedisLimiter(dead as never, new MemoryLimiter());
    expect(await l.hit('x', 1000)).toBe(1);
    expect(await l.hit('x', 1000)).toBe(2);
  });
});
