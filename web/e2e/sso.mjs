// SSO against a REAL OIDC provider (Dex, see deploy/sso-test). Asserts: allowed user gets in with the mapped role,
// a user without a mapped role is refused, and the token never stays in the address bar.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { chromium } from 'playwright-core';

const BASE = process.env.BASE ?? 'http://localhost:3000/ui/';
const exe = process.env.CHROMIUM ?? (existsSync('/opt/pw-browsers/chromium') ? '/opt/pw-browsers/chromium' : undefined);
const browser = await chromium.launch({ executablePath: exe, args: ['--no-sandbox'] });
const page = await (await browser.newContext()).newPage();
page.setDefaultTimeout(10000);

async function dexLogin(email) {
  await page.goto(BASE);
  await page.getByRole('link', { name: 'Entrar con SSO' }).click();
  await page.locator('input[name=login]').fill(email);
  await page.locator('input[name=password]').fill('password');
  await page.locator('button[type=submit]').click();
}

await dexLogin('admin@example.com');
await page.getByText('admin@example.com · admin').waitFor();
assert.equal(page.url().includes('token'), false, 'token must not remain in the URL');
await page.getByRole('button', { name: 'Usuarios' }).waitFor();            // admin-only tab proves the mapped role
console.log('ok - real IdP login maps to admin');
await page.getByRole('button', { name: 'Salir' }).click();

await page.context().clearCookies();
await dexLogin('nobody@example.com');
const alert = page.getByRole('alert');
await alert.waitFor();
assert.match(await alert.innerText(), /no AegisTrace role/);
assert.equal(page.url().includes('sso_error'), false, 'error is removed from the address bar after being shown');
console.log('ok - user without a mapped role is refused');
await browser.close();
console.log('SSO E2E passed');
