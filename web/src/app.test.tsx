import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setToken } from './api';
import { App, ApprovalsView } from './App';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
afterEach(() => { vi.restoreAllMocks(); sessionStorage.clear(); setToken(''); });

describe('web app', () => {
  it('logs in, shows the dashboard and hides the audit tab from analysts', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => String(url).endsWith('/auth/login')
      ? json({ token: 't', user: { userId: 'ana', orgId: 'org-acme', role: 'analyst' } })
      : json({ events: 7, alerts: 2, alertsBySeverity: { info: 0, low: 0, medium: 0, high: 1, critical: 1 }, openIncidents: 1, medianTriageMinutes: null, falsePositiveRate: null, pendingActions: 0 }));
    render(<App />);
    fireEvent.change(screen.getByLabelText('Contraseña'), { target: { value: 'demo-analyst' } });
    fireEvent.click(screen.getByText('Entrar'));
    await waitFor(() => expect(screen.getByText('Incidentes abiertos')).toBeInTheDocument());
    expect(screen.getByText('Aprobaciones')).toBeInTheDocument();
    expect(screen.queryByText('Auditoría')).not.toBeInTheDocument();
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
