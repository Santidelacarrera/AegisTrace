// Helper to build AEGIS_USERS entries:  npm run user-tool -- <password> [--mfa <userId>]
import { hashPassword } from '../src/auth.js';
import { newTotpSecret, otpauthUri } from '../src/totp.js';

const [password, flag, userId] = process.argv.slice(2);
if (!password) { console.error('usage: npm run user-tool -- <password> [--mfa <userId>]'); process.exit(1); }
const entry: Record<string, string> = { passwordHash: hashPassword(password) };
if (flag === '--mfa') {
  entry.totpSecret = newTotpSecret();
  console.error('Scan/enter in an authenticator app:', otpauthUri(entry.totpSecret, userId ?? 'user'));
}
console.log(JSON.stringify(entry));
