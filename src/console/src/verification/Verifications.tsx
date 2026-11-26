import { useEffect, useRef, useState } from 'react';
import { AuthError } from '../authentication/client';
import type { Identity } from '../authentication/client';
import { date } from '../user-management/client';
import { NewVerification } from './NewVerification';
import { filterNames, message, readVerificationPage, resultNames, statusNames } from './client';
import type { StatusFilter, VerificationPage } from './client';

// The digest is shortened so rows stay scannable. Sighted users get the whole value
// through the copy button; screen readers read it in full instead of the short form.
function Digest({ value }: { value?: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  useEffect(() => {
    if (state === 'idle') return;
    const timer = setTimeout(() => setState('idle'), 2500);
    return () => clearTimeout(timer);
  }, [state]);
  if (!value) return <>—</>;
  const copy = () => {
    void navigator.clipboard.writeText(value).then(() => setState('copied'), () => setState('failed'));
  };
  return <span className="digest">
    <code aria-hidden="true" title={value}>{`${value.slice(0, 15)}…${value.slice(-8)}`}</code>
    <span className="sr-only">{value}</span>
    <button type="button" onClick={copy} aria-label="Copiar la huella completa del reporte">Copiar</button>
    <span className="muted" role="status">{state === 'copied' ? 'Copiada' : state === 'failed' ? 'Error' : ''}</span>
  </span>;
}

// The list (ADR-0033 #9) shows result, codes and digest, never the JWS or claims.
// Starting a verification needs verification:start and recent MFA (ADR-0037).
export function Verifications({ identity, onAccessError, onStepUp }: { identity: Identity; onAccessError: (status: number) => void; onStepUp: () => void }) {
  const [status, setStatus] = useState<StatusFilter>('');
  const [cursor, setCursor] = useState('');
  const [page, setPage] = useState<VerificationPage | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [reload, setReload] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  const accessError = useRef(onAccessError); accessError.current = onAccessError;
  const canRead = identity.context!.capabilities.includes('verification:read');

  // Late results are discarded after a filter or page change, even if fetch ignores cancellation.
  useEffect(() => {
    setPage(null); setError('');
    if (!canRead) { setLoading(false); return; }
    const controller = new AbortController();
    setLoading(true);
    void readVerificationPage(identity, status, cursor, AbortSignal.any([controller.signal, AbortSignal.timeout(12000)]))
      .then(result => { if (!controller.signal.aborted) setPage(result); })
      .catch(cause => { if (!controller.signal.aborted) {
        setError(message(cause));
        if (cause instanceof AuthError && [401, 403, 404].includes(cause.status)) accessError.current(cause.status);
      } })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [status, cursor, reload, canRead]);

  if (!canRead) return <section aria-label="Verificaciones"><p role="status">No tienes permiso para consultar las verificaciones. Solicita acceso a tu administrador.</p></section>;
  return <section id="verifications" className="dashboard" aria-label="Verificaciones">
    {identity.context!.capabilities.includes('verification:start') &&
      <NewVerification identity={identity} onStepUp={onStepUp} onChanged={() => { setCursor(''); setReload(n => n + 1); }} />}
    <div className="verification-toolbar">
      <label>Estado<select value={status} onChange={e => { setCursor(''); setStatus(e.target.value as StatusFilter); }}>
        {(Object.keys(filterNames) as StatusFilter[]).map(key => <option key={key} value={key}>{filterNames[key]}</option>)}</select></label>
      <button disabled={loading} onClick={() => { setCursor(''); setReload(n => n + 1); }}>Actualizar verificaciones</button>
    </div>
    <section className="dashboard-activity" aria-labelledby="verifications-title" aria-busy={loading}>
      <h2 id="verifications-title" ref={heading} tabIndex={-1}>Sesiones de verificación</h2>
      {loading && <p role="status">Cargando verificaciones…</p>}
      {error && <p role="alert">{error}</p>}
      {page && (!page.items.length ? <p role="status">No hay verificaciones{status ? ' con este estado' : ''}.</p> :
        <div className="table-wrap"><table className="data-table"><caption className="sr-only">Sesiones de verificación de la organización, de la más reciente a la más antigua</caption>
          <thead><tr><th scope="col">Estado</th><th scope="col">Resultado</th><th scope="col">Códigos</th><th scope="col">Creada (UTC)</th><th scope="col">Caduca (UTC)</th><th scope="col">Sesión</th><th scope="col">Huella del reporte</th></tr></thead>
          <tbody>{page.items.map(item => <tr key={item.sessionId}>
            <td><span className="badge">{statusNames[item.status]}</span></td>
            <td>{item.result ? resultNames[item.result] : '—'}</td>
            <td className="record-id">{item.codes?.length ? item.codes.join(', ') : '—'}</td>
            <td><time dateTime={item.createdAt}>{date(item.createdAt)}</time></td>
            <td><time dateTime={item.expiresAt}>{date(item.expiresAt)}</time></td>
            <td className="record-id">{item.sessionId}</td>
            <td><Digest value={item.reportDigest} /></td></tr>)}</tbody></table></div>)}
      <div className="actions">
        <button disabled={loading} onClick={() => { setCursor(''); setReload(n => n + 1); }}>{cursor ? 'Volver al inicio' : 'Reiniciar lista'}</button>
        {page?.nextCursor && <button disabled={loading} onClick={() => { heading.current?.focus(); setCursor(page.nextCursor!); }}>Siguiente página</button>}
      </div>
    </section>
  </section>;
}
