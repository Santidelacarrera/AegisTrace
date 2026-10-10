import { AlertCandidate } from './rules.js';
import { NormEvent } from './types.js';

export type AnalyticsClient = (events: NormEvent[]) => Promise<AlertCandidate[]>;

const META: Record<string, { ruleId: string; ruleName: string; severity: AlertCandidate['severity']; title: (s: string) => string }> = {
  rate_spike: { ruleId: 'A100', ruleName: 'statistical_failure_spike', severity: 'medium', title: (s) => `Unusual burst of failures for ${s}` },
  new_source_ip: { ruleId: 'A110', ruleName: 'new_source_ip', severity: 'low', title: (s) => `Login from a new IP for ${s}` },
};

/** Client for the FastAPI analytics service. Fail-open: if the service is down, rule-based detection still works. */
export function httpAnalyticsClient(baseUrl: string, opts: { timeoutMs?: number; maxEvents?: number; fetchImpl?: typeof fetch; log?: (e: Record<string, unknown>) => void } = {}): AnalyticsClient {
  const doFetch = opts.fetchImpl ?? fetch;
  return async (events) => {
    const recent = [...events].sort((a, b) => a.timestamp.localeCompare(b.timestamp)).slice(-(opts.maxEvents ?? 5000));
    const byId = new Map(recent.map((e) => [e.id, e]));
    try {
      const res = await doFetch(`${baseUrl}/v1/anomalies`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ events: recent.map((e) => ({ id: e.id, timestamp: e.timestamp, type: e.type, user: e.user ?? null, ip: e.ip ?? null })) }),
        signal: AbortSignal.timeout(opts.timeoutMs ?? 3000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as { anomalies: { kind: string; subject: string; eventIds: string[]; explanation: string; score: number }[] };
      const out: AlertCandidate[] = [];
      for (const a of body.anomalies) {
        const m = META[a.kind];
        const evs = a.eventIds.map((i) => byId.get(i)).filter((e): e is NormEvent => !!e);   // never trust IDs the service invents
        if (!m || evs.length === 0) continue;
        out.push({ ruleId: m.ruleId, ruleName: m.ruleName, severity: m.severity, title: m.title(a.subject), explanation: `${a.explanation} (statistical, score ${a.score})`, subject: a.subject, events: evs });
      }
      return out;
    } catch (e) {
      opts.log?.({ msg: 'analytics_unavailable', error: String((e as Error).message) });
      return [];
    }
  };
}
