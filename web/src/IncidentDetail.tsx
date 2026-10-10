import { useCallback, useEffect, useState } from 'react';
import { Analysis, api, can, Detail, User } from './api';
import { Badge, ErrorBox } from './ui';

const NEXT: Record<string, string[]> = { open: ['triaging', 'false_positive'], triaging: ['contained', 'resolved', 'false_positive'], contained: ['resolved', 'triaging'], resolved: ['triaging'], false_positive: ['triaging'] };

export function IncidentDetail({ id, me, onBack }: { id: string; me: User; onBack: () => void }) {
  const [d, setD] = useState<Detail>(); const [err, setErr] = useState(''); const [comment, setComment] = useState(''); const [busy, setBusy] = useState(false);
  const load = useCallback(() => api<Detail>(`/incidents/${id}`).then(setD).catch((e) => setErr(e.message)), [id]);
  useEffect(() => { load(); }, [load]);
  const run = async (fn: () => Promise<unknown>) => { setErr(''); setBusy(true); try { await fn(); await load(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); } };
  if (!d) return <><button onClick={onBack}>← Volver</button><ErrorBox msg={err} /></>;
  const inc = d.incident, analysis: Analysis | undefined = d.analyses.at(-1), writer = can(me.role, 'write');
  return (
    <section>
      <button onClick={onBack}>← Volver</button>
      <h2>{inc.title} <Badge sev={inc.severity} /></h2>
      <p className="muted">Estado <b>{inc.status}</b> · responsable {inc.assignee ?? '—'} · {inc.firstSeen} → {inc.lastSeen} · etiquetas {inc.labels.join(', ') || '—'}</p>
      <ErrorBox msg={err} />
      {writer && <div className="toolbar">
        {(NEXT[inc.status] ?? []).map((s) => <button key={s} disabled={busy} onClick={() => run(() => api(`/incidents/${id}/status`, { method: 'POST', body: { status: s } }))}>→ {s}</button>)}
        <button disabled={busy} onClick={() => run(() => api(`/incidents/${id}/assignee`, { method: 'POST', body: { assignee: me.userId } }))}>Asignarme</button>
        <button className="primary" disabled={busy} onClick={() => run(() => api(`/incidents/${id}/analysis`, { method: 'POST' }))}>Solicitar análisis</button>
      </div>}

      <h3>Por qué se agruparon</h3>
      <ul>{inc.linkReasons.map((r, i) => <li key={i}>{r}</li>)}</ul>

      {analysis && <div className="card" aria-label="Análisis">
        <h3>Análisis asistido <span className="muted">({analysis.provider})</span></h3>
        <p>{analysis.summary}</p>
        <h4>Hipótesis</h4>
        <ul>{analysis.hypotheses.map((h, i) => <li key={i}>{h.statement} <i>(confianza {h.confidence})</i> <Cites ids={h.evidenceIds} /></li>)}</ul>
        <h4>Lo que no sabemos</h4>
        <ul>{analysis.gaps.map((g, i) => <li key={i}>{g}</li>)}{!analysis.gaps.length && <li className="muted">Sin lagunas declaradas.</li>}</ul>
        <h4>Recomendaciones <span className="muted">(solo sugerencias; ejecutar requiere aprobación humana)</span></h4>
        <ul>{analysis.recommendations.map((r) => (
          <li key={r.id}><b>{r.kind}</b> {r.target} — {r.rationale} <Cites ids={r.evidenceIds} />{' '}
            {r.executable && can(me.role, 'propose') && <button disabled={busy} onClick={() => run(() => api(`/incidents/${id}/actions`, { method: 'POST', body: { recommendationId: r.id } }))}>Proponer acción simulada</button>}
            {!r.executable && <span className="muted"> (no ejecutable)</span>}</li>))}</ul>
      </div>}

      {d.actions.length > 0 && <><h3>Acciones</h3><ul>{d.actions.map((a) => <li key={a.id}>{a.type} {a.target} — <b>{a.status}</b> {a.result}</li>)}</ul></>}

      <h3>Línea de tiempo</h3>
      <table><thead><tr><th>Hora</th><th>Tipo</th><th>Quién</th><th>Detalle</th></tr></thead>
        <tbody>{d.timeline.map((t, i) => <tr key={i}><td>{t.at}</td><td>{t.kind}</td><td>{t.actor}</td><td>{t.text} {t.kind === 'event' && <code>{t.refs[0]}</code>}</td></tr>)}</tbody></table>
      {writer && <form className="toolbar" onSubmit={(e) => { e.preventDefault(); if (comment) run(async () => { await api(`/incidents/${id}/comments`, { method: 'POST', body: { text: comment } }); setComment(''); }); }}>
        <input aria-label="Comentario" placeholder="Añadir comentario" value={comment} onChange={(e) => setComment(e.target.value)} /><button>Comentar</button></form>}
    </section>
  );
}

const Cites = ({ ids }: { ids: string[] }) => <span className="cites">{ids.slice(0, 4).map((i) => <code key={i}>{i}</code>)}{ids.length > 4 && <span className="muted"> +{ids.length - 4}</span>}</span>;
