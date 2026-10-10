import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { OrgData, Store } from './store.js';

export interface Queryable { query(text: string, params?: unknown[]): Promise<{ rows: any[] }> }

const COLLECTIONS = ['alerts', 'incidents', 'analyses', 'recommendations', 'actions'] as const;
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

/**
 * Write-through persistence: the in-memory org data stays the working set; every mutating request
 * is flushed (changed documents + new audit rows) to PostgreSQL before the response is sent, and the
 * working set is rebuilt from PostgreSQL on startup.
 */
export class PgPersistence {
  private seen = new Map<string, string>();   // `${org}|${collection}|${id}` -> content hash
  private auditSeq = new Map<string, number>();  // org -> last persisted seq
  private eventsSaved = new Map<string, Set<string>>();  // events are immutable: insert once, never re-hash
  constructor(private db: Queryable) {}

  async ping(): Promise<void> { await this.db.query('SELECT 1'); }

  async migrate(): Promise<void> {
    const sql = readFileSync(new URL('../migrations/001_init.sql', import.meta.url), 'utf8').replace(/--.*$/gm, '');
    for (const stmt of sql.split(';').map((x) => x.trim()).filter(Boolean)) await this.db.query(stmt);
  }

  async load(store: Store): Promise<void> {
    const docs = await this.db.query('SELECT organization_id, collection, id, body FROM aegis_doc');
    for (const r of docs.rows) {
      const org = store.org(r.organization_id);
      if (r.collection === 'lab') {
        org.lab.blockedIps = new Set(r.body.blockedIps); org.lab.disabledUsers = new Set(r.body.disabledUsers);
      } else {
        (org as any)[r.collection].set(r.id, r.body);
        if (r.collection === 'events') (this.eventsSaved.get(r.organization_id) ?? this.eventsSaved.set(r.organization_id, new Set()).get(r.organization_id)!).add(r.id);
      }
      if (r.collection !== 'events') this.seen.set(`${r.organization_id}|${r.collection}|${r.id}`, sha(JSON.stringify(r.body)));
    }
    const audit = await this.db.query('SELECT organization_id, seq, body FROM aegis_audit ORDER BY organization_id, seq');
    for (const r of audit.rows) {
      store.org(r.organization_id).audit.push(r.body);
      this.auditSeq.set(r.organization_id, Number(r.seq));
    }
  }

  async flush(store: Store, orgId: string): Promise<void> {
    const org: OrgData = store.org(orgId);
    const write = async (collection: string, id: string, body: unknown) => {
      const json = JSON.stringify(body), key = `${orgId}|${collection}|${id}`, h = sha(json);
      if (this.seen.get(key) === h) return;
      await this.db.query(
        `INSERT INTO aegis_doc (organization_id, collection, id, body) VALUES ($1,$2,$3,$4)
         ON CONFLICT (organization_id, collection, id) DO UPDATE SET body = EXCLUDED.body, updated_at = now()`,
        [orgId, collection, id, json]);
      this.seen.set(key, h);
    };
    // Events: batched multi-row insert of only the new ones.
    const saved = this.eventsSaved.get(orgId) ?? this.eventsSaved.set(orgId, new Set()).get(orgId)!;
    const fresh = [...org.events].filter(([id]) => !saved.has(id));
    for (let i = 0; i < fresh.length; i += 500) {
      const chunk = fresh.slice(i, i + 500);
      const params: unknown[] = [orgId];
      const values = chunk.map(([id, body], k) => { params.push(id, JSON.stringify(body)); return `($1,'events',$${2 * k + 2},$${2 * k + 3})`; });
      await this.db.query(`INSERT INTO aegis_doc (organization_id, collection, id, body) VALUES ${values.join(',')} ON CONFLICT (organization_id, collection, id) DO NOTHING`, params);
      chunk.forEach(([id]) => saved.add(id));
    }
    for (const c of COLLECTIONS) for (const [id, body] of (org as any)[c] as Map<string, unknown>) await write(c, id, body);
    await write('lab', 'state', { blockedIps: [...org.lab.blockedIps], disabledUsers: [...org.lab.disabledUsers] });
    const last = this.auditSeq.get(orgId) ?? 0;
    for (const e of org.audit.filter((a) => a.seq > last)) {
      await this.db.query('INSERT INTO aegis_audit (organization_id, seq, body) VALUES ($1,$2,$3)', [orgId, e.seq, JSON.stringify(e)]);
      this.auditSeq.set(orgId, e.seq);
    }
  }
}
