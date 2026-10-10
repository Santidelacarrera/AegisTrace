import { readFileSync } from 'node:fs';
import { evaluate, Labels } from '../src/evaluation.js';
import { EMPTY_CONTEXT, RuleContext } from '../src/rules.js';

const dir = new URL('../../data/synthetic/', import.meta.url);
const load = (prefix: string) => ({
  events: JSON.parse(readFileSync(new URL(`${prefix}events.json`, dir), 'utf8')),
  labels: JSON.parse(readFileSync(new URL(`${prefix}labels.json`, dir), 'utf8')) as Labels,
});
/** What an operator would configure for these synthetic orgs (service accounts, people allowed to approve role changes). */
export const CONTEXTS: Record<string, RuleContext> = {
  holdout: { serviceAccounts: ['lab.svc-*'], changeApprovers: ['lab.cto', 'lab.hr-admin'] },
  holdout2: { serviceAccounts: ['svc-*', 'ci-*', '*-bot'], changeApprovers: ['staff.vp-eng', 'staff.hr'] },
};
let failed = false;
const runs: [string, string, string, boolean][] = [
  ['dev (written with the rules)', '', 'dev', true],
  ['holdout 1 (used to tune R004/R005/context; no longer independent)', 'holdout-', 'holdout', false],
  ['holdout 2 (written after tuning, not tuned against)', 'holdout2-', 'holdout2', false],
];
for (const [name, prefix, ctxKey, gate] of runs) {
  const { events, labels } = load(prefix);
  for (const withCtx of ctxKey === 'dev' ? [false] : [false, true]) {
    const r = evaluate(events, labels, 'medium', withCtx ? CONTEXTS[ctxKey] : EMPTY_CONTEXT);
    console.log(`\n== ${name}${ctxKey === 'dev' ? '' : withCtx ? ' - WITH operator context' : ' - no context'}: ${events.length} events`);
    console.log(`alerts>=medium=${r.alerts} TP=${r.truePositives} FP=${r.falsePositives} | scenarios detected ${r.detectedScenarios}/${r.maliciousScenarios}`);
    console.log(`precision=${r.precision.toFixed(3)} recall=${r.recall.toFixed(3)} benign_scenarios_alerted=${(r.falsePositiveRate * 100).toFixed(1)}%`);
    console.log('missed by kind:', r.missedByKind, '\nfalse alarms by kind:', r.falseAlarmsByKind);
    if (gate && (r.precision < 0.9 || r.recall < 0.9)) failed = true;
  }
}
if (failed) { console.error('\nDev-set regression below 0.90'); process.exit(1); }
