import { useState } from 'react';
import { api, setToken, User } from './api';
import { ErrorBox } from './ui';

/** Password change (also the only screen available while a temporary password is active) and MFA self-service. */
export function Account({ me, forced, onChanged }: { me: User; forced?: boolean; onChanged: () => void }) {
  const [cur, setCur] = useState(''), [next, setNext] = useState(''), [msg, setMsg] = useState(''), [err, setErr] = useState('');
  const managed = me.source === 'store';
  const run = async (fn: () => Promise<void>) => { setErr(''); setMsg(''); try { await fn(); } catch (e) { setErr((e as Error).message); } };

  const changePassword = (e: React.FormEvent) => { e.preventDefault(); return run(async () => {
    const r = await api<{ token: string }>('/auth/password', { method: 'POST', body: { currentPassword: cur, newPassword: next } });
    setToken(r.token); setCur(''); setNext(''); setMsg('Contraseña actualizada. Las demás sesiones se han cerrado.'); onChanged();
  }); };

  return (
    <section>
      {forced && <p className="card" role="status">Estás usando una contraseña temporal. Debes cambiarla para continuar.</p>}
      {!managed && <p className="muted">Tu cuenta se gestiona fuera de la API (configuración o SSO): la contraseña y el MFA se cambian allí.</p>}
      {managed && <>
        <h3>Cambiar contraseña</h3>
        <form className="login card" onSubmit={changePassword} aria-label="Cambiar contraseña">
          <label>Contraseña actual<input type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} /></label>
          <label>Nueva contraseña (12+ caracteres)<input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></label>
          <button className="primary">Cambiar</button>
        </form>
        {!forced && <Mfa me={me} run={run} onChanged={onChanged} />}
      </>}
      {msg && <p role="status">{msg}</p>}
      <ErrorBox msg={err} />
    </section>
  );
}

function Mfa({ me, run, onChanged }: { me: User; run: (fn: () => Promise<void>) => Promise<void>; onChanged: () => void }) {
  const [pw, setPw] = useState(''), [code, setCode] = useState('');
  const [enroll, setEnroll] = useState<{ secret: string; otpauthUri: string }>();
  const [codes, setCodes] = useState<string[]>();
  return (
    <>
      <h3>Verificación en dos pasos (MFA)</h3>
      {codes ? (
        <div className="card" role="region" aria-label="Códigos de recuperación">
          <p><b>Guarda estos códigos ahora.</b> Cada uno sirve una vez si pierdes tu dispositivo, y no volverán a mostrarse.</p>
          <pre>{codes.join('\n')}</pre>
          <button onClick={() => { setCodes(undefined); onChanged(); }}>Los he guardado</button>
        </div>
      ) : me.mfa ? (
        <form className="login card" aria-label="Desactivar MFA" onSubmit={(e) => { e.preventDefault(); void run(async () => { await api('/auth/mfa/disable', { method: 'POST', body: { password: pw, code } }); setPw(''); setCode(''); onChanged(); }); }}>
          <p>MFA activado.</p>
          <label>Contraseña<input type="password" value={pw} onChange={(e) => setPw(e.target.value)} /></label>
          <label>Código o código de recuperación<input value={code} onChange={(e) => setCode(e.target.value)} /></label>
          <button>Desactivar MFA</button>
        </form>
      ) : enroll ? (
        <form className="login card" aria-label="Confirmar MFA" onSubmit={(e) => { e.preventDefault(); void run(async () => { const r = await api<{ recoveryCodes: string[] }>('/auth/mfa/confirm', { method: 'POST', body: { code } }); setCodes(r.recoveryCodes); setEnroll(undefined); setCode(''); }); }}>
          <p>Añade esta clave en tu app de autenticación (introdúcela a mano o usa el enlace otpauth):</p>
          <pre>{enroll.secret}</pre><small className="muted">{enroll.otpauthUri}</small>
          <label>Código de 6 dígitos<input inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} /></label>
          <button className="primary">Confirmar y activar</button>
        </form>
      ) : (
        <form className="login card" aria-label="Activar MFA" onSubmit={(e) => { e.preventDefault(); void run(async () => { setEnroll(await api('/auth/mfa/enroll', { method: 'POST', body: { password: pw } })); setPw(''); }); }}>
          <label>Contraseña<input type="password" value={pw} onChange={(e) => setPw(e.target.value)} /></label>
          <button>Activar MFA</button>
        </form>
      )}
    </>
  );
}
