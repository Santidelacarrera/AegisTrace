import { readFileSync } from 'node:fs';
import { evaluate, Labels } from '../src/evaluation.js';

const dir = new URL('../../data/synthetic/', import.meta.url);
const events = JSON.parse(readFileSync(new URL('events.json', dir), 'utf8'));
const labels = JSON.parse(readFileSync(new URL('labels.json', dir), 'utf8')) as Labels;
const r = evaluate(events, labels);
console.table({ ...r, missed: r.missed.join(',') || '-' });
console.log(`precision=${r.precision.toFixed(3)} recall=${r.recall.toFixed(3)} scenario_false_positive_rate=${r.falsePositiveRate.toFixed(3)}`);
if (r.precision < 0.9 || r.recall < 0.9) { console.error('Evaluation below threshold (0.90)'); process.exit(1); }
