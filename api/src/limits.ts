/** Fixed-window counters. In memory per process by default; Redis-backed so several API instances share limits. */
export interface Limiter {
  /** Increment the counter for `key` (window starts at the first hit) and return the new count. */
  hit(key: string, windowMs: number): Promise<number>;
  peek(key: string): Promise<number>;
  reset(key: string): Promise<void>;
}

export class MemoryLimiter implements Limiter {
  private m = new Map<string, { start: number; n: number }>();
  constructor(private now: () => number = Date.now) {}
  async hit(key: string, windowMs: number) {
    const t = this.now(), w = this.m.get(key);
    if (!w || t - w.start >= windowMs) { this.m.set(key, { start: t, n: 1 }); return 1; }
    return ++w.n;
  }
  async peek(key: string) { const w = this.m.get(key); return w ? w.n : 0; }
  async reset(key: string) { this.m.delete(key); }
}

interface RedisLike {
  eval(script: string, opts: { keys: string[]; arguments: string[] }): Promise<unknown>;
  get(key: string): Promise<string | null>;
  del(key: string): Promise<unknown>;
}

const HIT = `local n = redis.call('INCR', KEYS[1]) if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end return n`;

/** If Redis is unreachable the limiter degrades to the local in-memory one (and says so), rather than failing requests. */
export class RedisLimiter implements Limiter {
  constructor(private r: RedisLike, private fallback: Limiter, private log: (e: Record<string, unknown>) => void = () => undefined, private prefix = 'aegis:') {}
  private async guard<T>(fn: () => Promise<T>, fb: () => Promise<T>): Promise<T> {
    try { return await fn(); } catch (e) { this.log({ msg: 'redis_unavailable_using_local_limits', error: String((e as Error).message) }); return fb(); }
  }
  hit(key: string, windowMs: number) { return this.guard(async () => Number(await this.r.eval(HIT, { keys: [this.prefix + key], arguments: [String(windowMs)] })), () => this.fallback.hit(key, windowMs)); }
  peek(key: string) { return this.guard(async () => Number((await this.r.get(this.prefix + key)) ?? 0), () => this.fallback.peek(key)); }
  reset(key: string) { return this.guard(async () => { await this.r.del(this.prefix + key); }, () => this.fallback.reset(key)); }
}
