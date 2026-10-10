import { createHmac } from 'node:crypto';
import { AuditEntry } from './types.js';
import { OrgData } from './store.js';

const GENESIS = '0'.repeat(64);

function digest(key: string, e: Omit<AuditEntry, 'hash'>): string {
  const canonical = JSON.stringify([e.seq, e.at, e.orgId, e.actor, e.role, e.action, e.resourceType, e.resourceId, e.outcome, e.detail ?? null, e.prevHash]);
  return createHmac('sha256', key).update(canonical).digest('hex');
}

/** Append-only, HMAC-chained log per organization: editing, deleting or reordering an entry breaks verification. */
export function appendAudit(
  org: OrgData, key: string, at: string,
  e: Pick<AuditEntry, 'orgId' | 'actor' | 'role' | 'action' | 'resourceType' | 'resourceId' | 'outcome' | 'detail'>,
): AuditEntry {
  const prev = org.audit[org.audit.length - 1];
  const base = { seq: (prev?.seq ?? 0) + 1, at, ...e, prevHash: prev?.hash ?? GENESIS };
  const entry: AuditEntry = { ...base, hash: digest(key, base) };
  org.audit.push(entry);
  return entry;
}

/**
 * Verifies the chain. `head` (last hash) and `entries` should be anchored outside this system
 * (e.g. periodically exported to write-once storage) because a chain alone cannot reveal that
 * the newest entries were truncated.
 */
export function verifyAudit(org: OrgData, key: string, anchor?: { head: string; entries: number }): { valid: boolean; entries: number; head: string; brokenAt?: number; anchorMatch?: boolean } {
  let prev = GENESIS;
  for (const [i, e] of org.audit.entries()) {
    const { hash, ...rest } = e;
    if (e.prevHash !== prev || e.seq !== i + 1 || digest(key, rest) !== hash) return { valid: false, entries: org.audit.length, head: prev, brokenAt: e.seq };
    prev = hash;
  }
  const out = { valid: true, entries: org.audit.length, head: prev } as ReturnType<typeof verifyAudit>;
  if (anchor) {
    out.anchorMatch = anchor.entries === org.audit.length && anchor.head === prev;
    if (!out.anchorMatch) out.valid = false;
  }
  return out;
}
