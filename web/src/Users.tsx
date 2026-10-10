import { useCallback, useEffect, useState } from 'react';
import { api, ManagedUser, User } from './api';
import { ErrorBox } from './ui';

const ROLES = ['viewer', 'ingestor', 'analyst', 'approver', 'auditor', 'admin'];

export function Users({ me }: { me: User }) {
  const [items, setItems] = useState<ManagedUser[]>([]), [err, setErr] = useState(''), [secret, setSecret] = useState<{ userId: string; password: string }>();
  const [userId, setUserId] = useState(''), [role, setRole] = useState('analyst');
  const load = useCallback(() => api<{ items: ManagedUser[] }>('/users').then((r) => setItems(r.items)).catch((e) => setErr(e.message)), []);
  useEffect(() => { void load(); }, [load]);
  const act = async (fn: () => Promise<{ temporaryPassword?: string; user?: { userId: string } } | void>, who?: string) => {
    setErr(''); setSecret(undefined);
    try { const r = await fn(); if (r && 'temporaryPassword' in r && r.temporaryPassword) setSecret({ userId: who ?? r.user?.userId ?? '', password: r.temporaryPassword }); await load(); }
    catch (e) { setErr((e as Error).message); }
  };
  const post = (p: string, body?: unknown) => api<{ temporaryPassword?: string; user?: { userId: string } }>(p, { method: 'POST', body });
  return (
    <section>
      <form className="toolbar" aria-label="Crear usuario" onSubmit={(e) => { e.preventDefault(); void act(() => post('/users', { userId, role }), userId).then(() => setUserId('')); }}>
        <input aria-label="Identificador" placeholder="usuario (minúsculas, sin espacios)" value={userId} onChange={(e) => setUserId(e.target.value)} />
        <select aria-label="Rol" value={role} onChange={(e) => setRole(e.target.value)}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
        <button className="primary">Crear con contraseña temporal</button>
      </form>
      {secret && <div className="card" role="status"><b>Contraseña temporal de {secret.userId}</b> (se muestra una sola vez; deberá cambiarla al entrar):<pre>{secret.password}</pre></div>}
      <ErrorBox msg={err} />
      <table>
        <thead><tr><th>Usuario</th><th>Rol</th><th>Origen</th><th>MFA</th><th>Estado</th><th /></tr></thead>
        <tbody>{items.map((u) => {
          const editable = u.source === 'store' && u.userId !== me.userId;
          return (
            <tr key={u.userId}>
              <td>{u.userId}{u.mustChangePassword ? <span className="muted"> (contraseña temporal)</span> : null}</td>
              <td>{editable ? <select aria-label={`Rol de ${u.userId}`} value={u.role} onChange={(e) => void act(() => post(`/users/${u.userId}/role`, { role: e.target.value }))}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select> : u.role}</td>
              <td>{u.source === 'store' ? 'API' : 'configuración'}</td><td>{u.mfa ? 'sí' : 'no'}</td><td>{u.disabled ? 'desactivado' : 'activo'}</td>
              <td>{u.source === 'store' && <>
                <button onClick={() => void act(() => post(`/users/${u.userId}/reset-password`), u.userId)}>Resetear contraseña</button>{' '}
                {u.mfa && <button onClick={() => void act(() => post(`/users/${u.userId}/reset-mfa`))}>Quitar MFA</button>}{' '}
                {editable && <button onClick={() => void act(() => post(`/users/${u.userId}/${u.disabled ? 'enable' : 'disable'}`))}>{u.disabled ? 'Activar' : 'Desactivar'}</button>}
              </>}</td>
            </tr>);
        })}</tbody>
      </table>
    </section>
  );
}
