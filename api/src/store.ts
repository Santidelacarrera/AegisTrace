import { UserRecord } from './users.js';
import { Alert, Analysis, AuditEntry, Incident, NormEvent, Recommendation, ResponseAction } from './types.js';

/** All data for a single organization. The only way to reach it is Store.org(orgId). */
export class OrgData {
  events = new Map<string, NormEvent>();
  alerts = new Map<string, Alert>();
  incidents = new Map<string, Incident>();
  analyses = new Map<string, Analysis>();
  recommendations = new Map<string, Recommendation>();
  actions = new Map<string, ResponseAction>();
  users = new Map<string, UserRecord>();
  /** Event ids removed by retention, waiting to be deleted from the database on the next flush. */
  pendingEventDeletes: string[] = [];
  audit: AuditEntry[] = [];
  /** simulated lab state: nothing outside this object is ever touched */
  lab = { blockedIps: new Set<string>(), disabledUsers: new Set<string>() };
}

/**
 * In-memory repository. Every accessor is keyed by orgId, so a handler cannot read
 * another tenant's rows without explicitly passing a different orgId.
 * A PostgreSQL implementation would keep the same shape (see db/schema.sql).
 */
export class Store {
  private orgs = new Map<string, OrgData>();
  all(): IterableIterator<OrgData> { return this.orgs.values(); }
  /** True when the org already has data; lets unauthenticated paths avoid creating empty orgs for arbitrary ids. */
  ids(): string[] { return [...this.orgs.keys()]; }
  has(orgId: string) { return this.orgs.has(orgId); }
  org(orgId: string): OrgData {
    let o = this.orgs.get(orgId);
    if (!o) this.orgs.set(orgId, (o = new OrgData()));
    return o;
  }
}
