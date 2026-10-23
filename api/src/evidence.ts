import { createHash } from 'node:crypto';

/**
 * Evidence chain primitives: canonical JSON, a SHA-256 hash chain and its verification.
 * Format specification: docs/EVIDENCE-FORMAT.md (Nexus Security & AI Lab).
 *
 * The chain is publicly verifiable: anyone can recompute it without a secret. That also means whoever can
 * write records can recompute a whole chain. Tampering is detected when the head hash has been published
 * outside the system (an "anchor"); see verifyAnchor().
 */
export const EVIDENCE_FORMAT = 'aegistrace.evidence.v1' as const;
export const GENESIS_HASH = '0'.repeat(64);

export interface EvidenceInput {
  /** ISO-8601 UTC time of the fact being recorded */
  at: string;
  kind: string;
  source: string;
  actor: string;
  /** human-readable one-liner; the authoritative content is `data` */
  summary: string;
  refs: string[];
  data: Record<string, unknown>;
}

export interface EvidenceRecord extends EvidenceInput {
  /** 1-based position in the chain */
  seq: number;
  /** hash of the previous record, or GENESIS_HASH for the first */
  prev: string;
  /** sha256 over canonicalJson of every other field of the record */
  hash: string;
}

export type ChainFault =
  | 'malformed'
  | 'genesis_mismatch'
  | 'seq_gap'
  | 'prev_mismatch'
  | 'hash_mismatch'
  | 'claimed_head_mismatch'
  | 'anchor_mismatch';

export interface ChainVerification {
  valid: boolean;
  entries: number;
  /** hash of the last record that verified (GENESIS_HASH for an empty chain) */
  head: string;
  /** seq of the first record that failed */
  brokenAt?: number;
  reason?: ChainFault;
}

/**
 * Canonical JSON: object keys sorted by UTF-16 code unit, no whitespace, `undefined` members dropped,
 * arrays kept in order. Two implementations that follow this rule produce identical bytes for identical data.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
}

export function hashRecord(body: Omit<EvidenceRecord, 'hash'>): string {
  return createHash('sha256').update(canonicalJson(body)).digest('hex');
}

/** Builds the chain: seq starts at 1, each prev is the previous hash. */
export function buildChain(inputs: EvidenceInput[]): EvidenceRecord[] {
  let prev = GENESIS_HASH;
  return inputs.map((input, i) => {
    const body = { ...input, seq: i + 1, prev };
    const rec: EvidenceRecord = { ...body, hash: hashRecord(body) };
    prev = rec.hash;
    return rec;
  });
}

/** Recomputes every link. Reports the first failing record; never trusts stored hashes. */
export function verifyChain(records: unknown[]): ChainVerification {
  let prev = GENESIS_HASH;
  const fail = (reason: ChainFault, brokenAt: number): ChainVerification => ({ valid: false, entries: records.length, head: prev, brokenAt, reason });
  for (let i = 0; i < records.length; i++) {
    const r = records[i] as Partial<EvidenceRecord> | null;
    const expectedSeq = i + 1;
    if (!r || typeof r !== 'object' || typeof r.seq !== 'number' || typeof r.prev !== 'string' || typeof r.hash !== 'string') return fail('malformed', expectedSeq);
    if (r.seq !== expectedSeq) return fail('seq_gap', expectedSeq);
    if (r.prev !== prev) return fail(i === 0 ? 'genesis_mismatch' : 'prev_mismatch', expectedSeq);
    const { hash, ...body } = r as EvidenceRecord;
    if (hashRecord(body) !== hash) return fail('hash_mismatch', expectedSeq);
    prev = hash;
  }
  return { valid: true, entries: records.length, head: prev };
}

/**
 * Compares a verified chain against an externally published (head, entries) pair.
 * This is the only check that detects a truncated tail or a fully recomputed chain.
 */
export function verifyAnchor(v: ChainVerification, anchor?: { head: string; entries: number }): ChainVerification {
  if (!anchor || !v.valid) return v;
  if (v.entries !== anchor.entries || v.head !== anchor.head) return { ...v, valid: false, reason: 'anchor_mismatch' };
  return v;
}
