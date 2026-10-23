// Verifies an evidence bundle offline: no server, no secret. Exit 0 = valid, 1 = invalid, 2 = usage error.
//   npm run verify-evidence -- <bundle.json> [--anchor-head <hex> --anchor-entries <n>]
import { readFileSync } from 'node:fs';
import { verifyEvidenceBundle } from '../src/forensic.js';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
const flag = (name: string) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
if (!file) { console.error('usage: npm run verify-evidence -- <bundle.json> [--anchor-head <hex> --anchor-entries <n>]'); process.exit(2); }

const head = flag('--anchor-head');
const entries = flag('--anchor-entries');
const anchor = head && entries !== undefined ? { head, entries: Number(entries) } : undefined;
const result = verifyEvidenceBundle(JSON.parse(readFileSync(file, 'utf8')), anchor);
console.log(JSON.stringify(result, null, 2));
process.exit(result.valid ? 0 : 1);
