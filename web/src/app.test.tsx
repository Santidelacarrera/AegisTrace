import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setToken } from './api';
import { App, ApprovalsView } from './App';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
afterEach(() => { vi.restoreAllMocks(); sessionStorage.clear(); setToken(''); });

describe('web app', () => {
  it('logs in, shows the dashboard and hides the audit tab from analysts', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => String(url).endsWith('/auth/config') ? json({ password: true, oidc: false }) : String(url).endsWith('/auth/login')
      ? json({ token: 't', user: { userId: 'ana', orgId: 'org-acme', role: 'analyst' } })
      : json({ events: 7, alerts: 2, alertsBySeverity: { info: 0, low: 0, medium: 0, high: 1, critical: 1 }, openIncidents: 1, medianTriageMinutes: null, falsePositiveRate: null, pendingActions: 0 }));
    render(<App />);
    fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'demo-analyst' } });
    fireEvent.click(screen.getByText('Entrar'));
    await waitFor(() => expect(screen.getByText('Incidentes abiertos')).toBeInTheDocument());
    expect(screen.getByText('Aprobaciones')).toBeInTheDocument();
    expect(screen.queryByText('Auditoría')).not.toBeInTheDocument();
  });
  it('asks for the MFA code only after the server requires it', async () => {
    const bodies: unknown[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
      if (String(url).endsWith('/auth/config')) return json({ password: true, oidc: true });
      bodies.push(JSON.parse(String(init?.body)));
      return bodies.length === 1 ? json({ error: 'mfa_required', message: 'A one-time code is required' }, 401)
        : json({ token: 't', user: { userId: 'alex', orgId: 'org-acme', role: 'approver' } });
    });
    render(<App />);
    expect(await screen.findByText('Entrar con SSO')).toHaveAttribute('href', '/api/v1/auth/oidc/login');
    expect(screen.queryByLabelText('Código de verificación')).not.toBeInTheDocument();
    fireEvent.click(screen.getByText('Entrar'));
    const code = await screen.findByLabelText('Código de verificación');
    fireEvent.change(code, { target: { value: '123456' } });
    fireEvent.click(screen.getByText('Entrar'));
    await waitFor(() => expect(bodies[1]).toMatchObject({ code: '123456' }));
  });
  it('completes an SSO login from the URL fragment and removes the token from the address bar', async () => {
    history.replaceState(null, '', '/ui/#token=abc.def');
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => String(url).endsWith('/auth/me') ? json({ userId: 'sam@example.com', orgId: 'org-acme', role: 'admin' }) : json({ events: 0, alerts: 0, alertsBySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, openIncidents: 0, medianTriageMinutes: null, falsePositiveRate: null, pendingActions: 0 }));
    render(<App />);
    expect(await screen.findByText(/sam@example.com · admin/)).toBeInTheDocument();
    expect(window.location.hash).toBe('');
  });
  it('shows server errors on failed login', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ error: 'invalid_credentials', message: 'Invalid credentials' }, 401));
    render(<App />);
    fireEvent.click(screen.getByText('Entrar'));
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid credentials');
  });
  it('disables self-approval and escapes untrusted text', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [
      { id: 'a1', incidentId: 'i', type: 'block_ip', target: '203.0.113.9', status: 'pending_approval', proposedBy: 'alex', mode: 'simulated' },
      { id: 'a2', incidentId: 'i', type: 'disable_user', target: '<img src=x onerror=alert(1)>', status: 'pending_approval', proposedBy: 'ana', mode: 'simulated' },
    ] }));
    const { container } = render(<ApprovalsView me={{ userId: 'alex', orgId: 'o', role: 'approver' }} />);
    const buttons = await screen.findAllByText('Aprobar');
    expect(buttons[0]).toBeDisabled();
    expect(buttons[1]).toBeEnabled();
    expect(container.querySelector('img')).toBeNull();
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
  });
});
