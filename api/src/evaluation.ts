import { detect } from './rules.js';
import { normalizeEvent } from './normalize.js';
import { NormEvent, sevRank } from './types.js';

export interface Labels { scenarios: Record<string, { malicious: boolean; kind: string }>; events: Record<string, string> }

export interface EvalReport {
  alerts: number; truePositives: number; falsePositives: number;
  maliciousScenarios: number; detectedScenarios: number; missed: string[];
  precision: number; recall: number; falsePositiveRate: number;
  missedByKind: Record<string, number>; falseAlarmsByKind: Record<string, number>;
}

/** Scenario-level evaluation of alerts with severity >= medium against labeled synthetic data. */
export function evaluate(rawEvents: unknown[], labels: Labels, minSeverity: 'medium' | 'low' = 'medium'): EvalReport {
  const events: NormEvent[] = rawEvents.map((r) => {
    const n = normalizeEvent(r, 'eval');
    if (!n.ok) throw new Error('dataset contains invalid event: ' + n.error);
    return n.event;
  });
  const alerts = detect(events).filter((a) => sevRank(a.severity) >= sevRank(minSeverity));
  let tp = 0, fp = 0;
  const falseAlarmsByKind: Record<string, number> = {};
  const hit = new Set<string>();
  for (const a of alerts) {
    const scen = a.events.map((e) => labels.events[e.id]).filter((s): s is string => !!s);
    const malicious = scen.filter((s) => labels.scenarios[s]?.malicious);
    if (malicious.length > a.events.length / 2) { tp++; malicious.forEach((s) => hit.add(s)); } else { fp++; const k = labels.scenarios[scen[0] ?? '']?.kind ?? 'unlabeled'; falseAlarmsByKind[k] = (falseAlarmsByKind[k] ?? 0) + 1; }
  }
  const mal = Object.entries(labels.scenarios).filter(([, v]) => v.malicious).map(([k]) => k);
  const benign = Object.entries(labels.scenarios).filter(([, v]) => !v.malicious).length;
  const benignAlerted = new Set<string>();
  for (const a of alerts) for (const e of a.events) { const s = labels.events[e.id]; if (s && !labels.scenarios[s]?.malicious) benignAlerted.add(s); }
  return {
    alerts: alerts.length, truePositives: tp, falsePositives: fp,
    maliciousScenarios: mal.length, detectedScenarios: mal.filter((s) => hit.has(s)).length,
    missed: mal.filter((s) => !hit.has(s)),
    missedByKind: Object.fromEntries([...new Set(mal.filter((x) => !hit.has(x)).map((x) => labels.scenarios[x]!.kind))].map((k) => [k, mal.filter((x) => !hit.has(x) && labels.scenarios[x]!.kind === k).length])),
    falseAlarmsByKind,
    precision: alerts.length ? tp / alerts.length : 1,
    recall: mal.length ? mal.filter((s) => hit.has(s)).length / mal.length : 1,
    falsePositiveRate: benign ? benignAlerted.size / benign : 0,
  };
}
