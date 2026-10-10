// Prints normalized events (JSON) for a dataset file, so other tools (analytics/evaluate.py) see what the API sees.
import { readFileSync } from 'node:fs';
import { normalizeEvent } from '../src/normalize.js';

const raw = JSON.parse(readFileSync(process.argv[2]!, 'utf8')) as unknown[];
console.log(JSON.stringify(raw.map((x) => normalizeEvent(x, 'eval')).flatMap((n) => (n.ok ? [n.event] : []))));
