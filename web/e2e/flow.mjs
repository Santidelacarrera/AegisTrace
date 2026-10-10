// Browser E2E with assertions: analyst -> analysis -> proposal; approver -> approval; auditor -> audit chain.
// Needs the API on BASE (default http://localhost:3000/ui/) with the synthetic dataset ingested. CI runs it; see .github/workflows/ci.yml.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { chromium } from 'playwright-core';

const BASE = process.env.BASE ?? 'http://localhost:3000/ui/';
const exe = process.env.CHROMIUM ?? (existsSync('/opt/pw-browsers/chromium') ? '/opt/pw-browsers/chromium' : undefined);
const browser = await chromium.launch({ executablePath: exe, args: ['--no-sandbox'] });
const page = await (await browser.newContext({ viewport: { width: 1280, height: 800 } })).newPage();
page.setDefaultTimeout(8000);
const errors = [];
page.on('pageerror', (e) => errors.push(String(e)));

async function login(user, role) {
  await page.goto(BASE);
  await page.getByLabel('Usuario').fill(user);
  await page.getByLabel('Contraseña').fill('demo-' + role);
  await page.getByRole('button', { name: 'Entrar' }).click();
  await page.getByText(`${user} ·`).waitFor();
}
const logout = () => page.getByRole('button', { name: 'Salir' }).click();
const step = (n) => console.log('ok -', n);

// wrong password is rejected and visible
await page.goto(BASE);
await page.getByLabel('Contraseña').fill('nope');
await page.getByRole('button', { name: 'Entrar' }).click();
assert.match(await page.getByRole('alert').innerText(), /Invalid credentials/);
step('bad login rejected');

// analyst
await login('ana', 'analyst');
await page.getByText('Incidentes abiertos').waitFor();
assert.equal(await page.getByRole('button', { name: 'Auditoría' }).count(), 0, 'analyst must not see the audit tab');
await page.getByRole('button', { name: 'Incidentes' }).click();
await page.getByLabel('Severidad').selectOption('critical');
await page.locator('tr.row').first().click();
await page.getByRole('button', { name: '→ triaging' }).click();
await page.getByText('triaging', { exact: true }).first().waitFor();
await page.getByRole('button', { name: 'Solicitar análisis' }).click();
const analysis = page.getByLabel('Análisis');
await analysis.waitFor();
const text = await analysis.innerText();
assert.match(text, /Lo que no sabemos/);
assert.match(text, /No MFA, device or geolocation data/);
assert.ok((await analysis.locator('.cites code').count()) > 0, 'analysis must show cited event IDs');
step('analysis shows citations and data gaps');
await page.getByRole('button', { name: 'Proponer acción simulada' }).first().click();
await page.getByText('pending_approval').first().waitFor();
await logout();

// approver
await login('alex', 'approver');
await page.getByRole('button', { name: 'Aprobaciones' }).click();
await page.getByText('pending_approval').first().waitFor();
await page.getByRole('button', { name: 'Aprobar' }).first().click();
await page.getByText('executed').first().waitFor();
assert.match(await page.locator('tbody').innerText(), /SIMULATED/);
step('approval executes a simulated action');
await logout();

// auditor
await login('aude', 'auditor');
await page.getByRole('button', { name: 'Auditoría' }).click();
await page.getByRole('button', { name: 'Verificar integridad' }).click();
await page.getByRole('status').filter({ hasText: /\S/ }).waitFor();
assert.match(await page.getByRole('status').innerText(), /Cadena íntegra/);
const rows = await page.locator('tbody').innerText();
for (const a of ['action.propose', 'action.approve', 'action.execute', 'auth.login']) assert.match(rows, new RegExp(a));
step('audit trail intact and complete');

assert.deepEqual(errors, [], 'no uncaught page errors');
await browser.close();
console.log('E2E passed');
