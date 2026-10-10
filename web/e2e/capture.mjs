// Captures README screenshots and a walkthrough video against a running stack (API on :3000 with seeded data).
// Usage: node e2e/capture.mjs   (set CHROMIUM=/path/to/chromium if not at the default)
import { chromium } from 'playwright-core';
import { existsSync, mkdirSync, renameSync, readdirSync } from 'node:fs';

const BASE = process.env.BASE ?? 'http://localhost:3000/ui/';
const OUT = new URL('../../docs/media/', import.meta.url).pathname;
const VID = OUT + 'video-tmp/';
mkdirSync(VID, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM ?? (existsSync('/opt/pw-browsers/chromium') ? '/opt/pw-browsers/chromium' : undefined), args: ['--no-sandbox'] });
const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, colorScheme: 'light', recordVideo: { dir: VID, size: { width: 1280, height: 800 } } });
const page = await ctx.newPage();
const pause = (ms = 900) => page.waitForTimeout(ms);
const shot = (name) => page.screenshot({ path: OUT + name + '.png' });

async function login(user, role) {
  await page.goto(BASE); await pause(500);
  await page.getByLabel('Usuario').fill(user);
  await page.getByLabel('Contraseña').fill('demo-' + role);
  await page.getByRole('button', { name: 'Entrar' }).click();
  await page.getByText(user + ' ·').waitFor(); await pause();
}
const logout = async () => { await page.getByRole('button', { name: 'Salir' }).click(); await pause(400); };

// 1. analyst: dashboard -> incidents -> critical incident -> analysis -> propose action
await page.goto(BASE); await pause(600); await shot('00-login');
await login('ana', 'analyst'); await shot('01-dashboard');
await page.getByRole('button', { name: 'Incidentes' }).click(); await pause(); await page.getByLabel('Severidad').selectOption('critical'); await pause(); await shot('02-incidents');
await page.locator('tr.row').first().click(); await pause();
await page.getByRole('button', { name: '→ triaging' }).click(); await pause();
await page.getByRole('button', { name: 'Solicitar análisis' }).click(); await page.getByLabel('Análisis').waitFor(); await pause(1200);
await page.getByLabel('Análisis').scrollIntoViewIfNeeded(); await shot('03-incident-analysis');
await page.getByRole('button', { name: 'Proponer acción simulada' }).first().click(); await pause(1200); await shot('04-action-proposed');
await logout();

// 2. approver: approve the simulated action
await login('alex', 'approver');
await page.getByRole('button', { name: 'Aprobaciones' }).click(); await pause(); await shot('05-approvals');
await page.getByRole('button', { name: 'Aprobar' }).first().click(); await pause(1200); await shot('06-approved');
await logout();

// 3. auditor: audit trail + verify
await login('aude', 'auditor');
await page.getByRole('button', { name: 'Auditoría' }).click(); await pause();
await page.getByRole('button', { name: 'Verificar integridad' }).click(); await pause(1200); await shot('07-audit');
await logout();

// 4. admin: user management; own account (MFA)
await login('root-admin', 'admin');
await page.getByRole('button', { name: 'Usuarios' }).click(); await pause();
await page.getByLabel('Identificador').fill('carla'); await page.getByLabel('Rol').selectOption('analyst');
await page.getByRole('button', { name: 'Crear con contraseña temporal' }).click(); await pause(1200); await shot('08-users');
await page.getByRole('button', { name: 'Mi cuenta' }).click(); await pause(); await shot('09-account');
await ctx.close(); await browser.close();
const f = readdirSync(VID).find((x) => x.endsWith('.webm'));
renameSync(VID + f, OUT + 'demo.webm');
console.log('wrote screenshots + docs/media/demo.webm');
