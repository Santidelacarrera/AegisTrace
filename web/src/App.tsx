import { useCallback, useEffect, useState } from 'react';
import { api, ApiError, can, Dashboard as Dash, hasToken, Incident, setToken, User, Action } from './api';
import { Account } from './Account';
import { IncidentDetail } from './IncidentDetail';
import { Users } from './Users';
import { Badge, ErrorBox } from './ui';

function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const initialErr = (() => { const m = window.location.hash.match(/^#sso_error=(.+)$/); if (!m) return ''; history.replaceState(null, '', window.location.pathname); try { return `SSO: ${decodeURIComponent(m[1]!)}`; } catch { return 'SSO: error'; } })();
  const [orgId, setOrg] = useState('org-acme'), [userId, setUser] = useState('ana'), [password, setPw] = useState(''), [code, setCode] = useState(''), [needCode, setNeedCode] = useState(false), [sso, setSso] = useState(false), [err, setErr] = useState(initialErr);
  useEffect(() => { api<{ oidc: boolean }>('/auth/config').then((c) => setSso(c.oidc)).catch(() => undefined); }, []);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr('');
    try { const r = await api<{ token: string; user: User }>('/auth/login', { method: 'POST', body: { orgId, userId, password, ...(code ? { code } : {}) } }); setToken(r.token); onLogin(await api<User>('/auth/me').catch(() => r.user)); }
    catch (x) { if (x instanceof ApiError && x.code === 'mfa_required') { setNeedCode(true); setErr('Introduce el código de tu app de autenticación.'); } else setErr((x as Error).message); }
  };
  return (
    <form className="login card" onSubmit={submit} aria-label="Iniciar sesión">
      <h1>AegisTrace</h1>
      <label>Organización<input value={orgId} onChange={(e) => setOrg(e.target.value)} /></label>
      <label>Usuario<input value={userId} onChange={(e) => setUser(e.target.value)} autoComplete="username" /></label>
      <label>Contraseña<input type="password" value={password} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" /></label>
      {needCode && <label>Código de verificación<input inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} /></label>}
      <button className="primary">Entrar</button>
      {sso && <a className="sso" href="/api/v1/auth/oidc/login">Entrar con SSO</a>}
      <ErrorBox msg={err} />
      <p className="muted">Demo (solo desarrollo): contraseña <code>demo-&lt;rol&gt;</code>, p. ej. <code>demo-analyst</code>.</p>
    </form>
  );
}

function DashboardView() {
  const [d, setD] = useState<Dash>(); const [err, setErr] = useState('');
  useEffect(() => { api<Dash>('/dashboard').then(setD).catch((e) => setErr(e.message)); }, []);
  if (!d) return <ErrorBox msg={err} />;
  const cards: [string, string | number][] = [['Eventos', d.events], ['Alertas', d.alerts], ['Incidentes abiertos', d.openIncidents], ['Acciones pendientes', d.pendingActions],
    ['Triage mediano (min)', d.medianTriageMinutes === null ? '—' : d.medianTriageMinutes.toFixed(1)], ['Falsos positivos', d.falsePositiveRate === null ? '—' : `${Math.round(d.falsePositiveRate * 100)}%`]];
  return (
    <section>
      <div className="cards">{cards.map(([k, v]) => <div className="card stat" key={k}><b>{v}</b><span>{k}</span></div>)}</div>
      <h3>Alertas por severidad</h3>
      <div className="cards">{(Object.entries(d.alertsBySeverity)).map(([s, n]) => <div className="card stat" key={s}><b>{n}</b><Badge sev={s} /></div>)}</div>
    </section>
  );
}

function IncidentsView({ onOpen }: { onOpen: (id: string) => void }) {
  const [items, setItems] = useState<Incident[]>([]); const [q, setQ] = useState(''), [status, setStatus] = useState(''), [sev, setSev] = useState(''), [err, setErr] = useState('');
  useEffect(() => {
    const p = new URLSearchParams({ limit: '100' }); if (q) p.set('q', q); if (status) p.set('status', status); if (sev) p.set('severity', sev);
    api<{ items: Incident[] }>('/incidents?' + p).then((r) => setItems(r.items)).catch((e) => setErr(e.message));
  }, [q, status, sev]);
  return (
    <section>
      <div className="toolbar">
        <input aria-label="Buscar incidentes" placeholder="Buscar usuario, IP, título…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select aria-label="Estado" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Todos los estados</option>{['open', 'triaging', 'contained', 'resolved', 'false_positive'].map((s) => <option key={s}>{s}</option>)}</select>
        <select aria-label="Severidad" value={sev} onChange={(e) => setSev(e.target.value)}><option value="">Toda severidad</option>{['critical', 'high', 'medium', 'low'].map((s) => <option key={s}>{s}</option>)}</select>
      </div>
      <ErrorBox msg={err} />
      <table>
        <thead><tr><th>Severidad</th><th>Estado</th><th>Título</th><th>Entidades</th><th>Eventos</th></tr></thead>
        <tbody>{items.map((i) => (
          <tr key={i.id} className="row" tabIndex={0} onClick={() => onOpen(i.id)} onKeyDown={(e) => e.key === 'Enter' && onOpen(i.id)}>
            <td><Badge sev={i.severity} /></td><td>{i.status}</td><td>{i.title}</td><td>{[...i.users, ...i.ips].join(', ')}</td><td>{i.eventIds.length}</td>
          </tr>))}
          {!items.length && <tr><td colSpan={5} className="muted">Sin incidentes.</td></tr>}</tbody>
      </table>
    </section>
  );
}

export function ApprovalsView({ me }: { me: User }) {
  const [items, setItems] = useState<Action[]>([]); const [err, setErr] = useState('');
  const load = useCallback(() => api<{ items: Action[] }>('/actions').then((r) => setItems(r.items)).catch((e) => setErr(e.message)), []);
  useEffect(() => { load(); }, [load]);
  const decide = async (id: string, what: 'approve' | 'reject') => { setErr(''); try { await api(`/actions/${id}/${what}`, { method: 'POST' }); await load(); } catch (e) { setErr((e as ApiError).message); } };
  return (
    <section>
      <p className="muted">Todas las acciones son <b>simuladas</b> y limitadas al ámbito de laboratorio. Quien propone no puede aprobar.</p>
      <ErrorBox msg={err} />
      <table>
        <thead><tr><th>Acción</th><th>Objetivo</th><th>Estado</th><th>Propuesta por</th><th>Resultado</th><th /></tr></thead>
        <tbody>{items.map((a) => (
          <tr key={a.id}><td>{a.type}</td><td>{a.target}</td><td>{a.status}</td><td>{a.proposedBy}</td><td>{a.result ?? ''}</td>
            <td>{a.status === 'pending_approval' && can(me.role, 'approve') && <>
              <button disabled={a.proposedBy === me.userId} title={a.proposedBy === me.userId ? 'No puedes aprobar tu propia propuesta' : ''} className="primary" onClick={() => decide(a.id, 'approve')}>Aprobar</button>{' '}
              <button onClick={() => decide(a.id, 'reject')}>Rechazar</button></>}</td></tr>))}
          {!items.length && <tr><td colSpan={6} className="muted">Sin acciones.</td></tr>}</tbody>
      </table>
    </section>
  );
}

function AuditView() {
  const [rows, setRows] = useState<Record<string, string>[]>([]); const [v, setV] = useState(''); const [err, setErr] = useState('');
  useEffect(() => { api<{ items: Record<string, string>[] }>('/audit?limit=200').then((r) => setRows(r.items.slice().reverse())).catch((e) => setErr(e.message)); }, []);
  const verify = async () => { const r = await api<{ valid: boolean; entries: number; anchorMatch?: boolean }>('/audit/verify'); setV(r.valid ? `Cadena íntegra (${r.entries} entradas)${r.anchorMatch ? ', ancla externa coincide' : ''}` : 'CADENA ALTERADA'); };
  return (
    <section>
      <button onClick={verify}>Verificar integridad</button> <span role="status">{v}</span><ErrorBox msg={err} />
      <table><thead><tr><th>#</th><th>Hora</th><th>Quién</th><th>Acción</th><th>Recurso</th><th>Resultado</th><th>Detalle</th></tr></thead>
        <tbody>{rows.map((r) => <tr key={r.seq}><td>{r.seq}</td><td>{r.at}</td><td>{r.actor} ({r.role})</td><td>{r.action}</td><td>{r.resourceType}:{r.resourceId}</td><td>{r.outcome}</td><td>{r.detail}</td></tr>)}</tbody></table>
    </section>
  );
}

export function App() {
  const [user, setUser] = useState<User>(); const [tab, setTab] = useState<'dash' | 'inc' | 'appr' | 'audit' | 'users' | 'acct'>('dash'); const [open, setOpen] = useState<string>();
  useEffect(() => {
    // SSO callback returns to /ui/#token=...; take it, clear it from the address bar, and load who we are.
    const m = window.location.hash.match(/^#token=(.+)$/);
    if (m) {
      history.replaceState(null, '', window.location.pathname);
      setToken(m[1]!);
      api<User>('/auth/me').then(login).catch(() => setToken(''));
      return;
    }
    if (hasToken()) { /* validate session */ api<User>('/auth/me').then(login).catch(() => setToken('')); }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const login = (u: User) => { try { sessionStorage.setItem('aegis.user', JSON.stringify(u)); } catch { /* ignore */ } setUser(u); };
  const refresh = () => { api<User>('/auth/me').then(login).catch(() => undefined); };
  if (!user) return <Login onLogin={login} />;
  if (user.mustChangePassword) return <main><h1>AegisTrace</h1><Account me={user} forced onChanged={refresh} /></main>;
  const tabs: [typeof tab, string][] = [['dash', 'Panel'], ['inc', 'Incidentes'], ['appr', 'Aprobaciones'], ...(can(user.role, 'audit') ? [['audit', 'Auditoría'] as [typeof tab, string]] : []), ...(can(user.role, 'users') ? [['users', 'Usuarios'] as [typeof tab, string]] : []), ['acct', 'Mi cuenta']];
  return (
    <>
      <header><h1>AegisTrace</h1>
        <nav>{tabs.map(([k, l]) => <button key={k} aria-current={tab === k && !open} className={tab === k && !open ? 'tab active' : 'tab'} onClick={() => { setTab(k); setOpen(undefined); }}>{l}</button>)}</nav>
        <span className="spacer" /><span className="muted">{user.userId} · {user.role} · {user.orgId}</span>
        <button onClick={() => { setToken(''); setUser(undefined); }}>Salir</button></header>
      <main>
        {open ? <IncidentDetail id={open} me={user} onBack={() => setOpen(undefined)} />
          : tab === 'dash' ? <DashboardView /> : tab === 'inc' ? <IncidentsView onOpen={setOpen} /> : tab === 'appr' ? <ApprovalsView me={user} /> : tab === 'users' ? <Users me={user} /> : tab === 'acct' ? <Account me={user} onChanged={refresh} /> : <AuditView />}
      </main>
    </>
  );
}
