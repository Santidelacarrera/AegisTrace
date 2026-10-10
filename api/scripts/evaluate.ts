import { readFileSync } from 'node:fs';
import { evaluate, Labels } from '../src/evaluation.js';

const dir = new URL('../../data/synthetic/', import.meta.url);
const load = (prefix: string) => ({
  events: JSON.parse(readFileSync(new URL(`${prefix}events.json`, dir), 'utf8')),
  labels: JSON.parse(readFileSync(new URL(`${prefix}labels.json`, dir), 'utf8')) as Labels,
});
let failed = false;
for (const [name, prefix, gate] of [['dev (tuned alongside the rules)', '', true], ['holdout (not used for tuning)', 'holdout-', false]] as const) {
  const { events, labels } = load(prefix);
  const r = evaluate(events, labels);
  console.log(`\n== ${name}: ${events.length} events`);
  console.log(`alerts>=medium=${r.alerts} TP=${r.truePositives} FP=${r.falsePositives} | scenarios detected ${r.detectedScenarios}/${r.maliciousScenarios}`);
  console.log(`precision=${r.precision.toFixed(3)} recall=${r.recall.toFixed(3)} benign_scenarios_alerted=${(r.falsePositiveRate * 100).toFixed(1)}%`);
  console.log('missed by kind:', r.missedByKind, '\nfalse alarms by kind:', r.falseAlarmsByKind);
  if (gate && (r.precision < 0.9 || r.recall < 0.9)) failed = true;
}
if (failed) { console.error('\nDev-set regression below 0.90'); process.exit(1); }
