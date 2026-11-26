import QRCode from 'qrcode';
import { useEffect, useRef, useState } from 'react';
import { AuthError } from '../authentication/client';
import type { Identity } from '../authentication/client';
import { readVerification, resultNames, startVerification } from './client';
import type { StartedVerification, VerificationSession } from './client';

type Active = StartedVerification & { image: string };

function startError(cause: unknown): string {
  if (cause instanceof AuthError) {
    if (cause.code === 'step_up_required') return 'Necesitas una verificación de identidad reciente para crear una verificación.';
    if (cause.status === 403) return 'No tienes permiso para crear verificaciones o tu acceso cambió.';
    if (cause.status === 429) return 'Hay demasiadas verificaciones abiertas. Espera a que caduquen.';
    if (cause.status === 503) return 'El verificador no está disponible o no está configurado.';
  }
  return 'No pudimos crear la verificación. Comprueba tu conexión y reintenta.';
}

// The launch URI is shown only as a QR code while the session is open; it is not stored.
export function NewVerification({ identity, onStepUp, onChanged }: { identity: Identity; onStepUp: () => void; onChanged: () => void }) {
  const [active, setActive] = useState<Active | null>(null);
  const [result, setResult] = useState<VerificationSession | null>(null);
  const [error, setError] = useState('');
  const [needsStepUp, setNeedsStepUp] = useState(false);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(Date.now());
  const changed = useRef(onChanged); changed.current = onChanged;

  const expired = !!active && now >= Date.parse(active.expiresAt);
  const finished = result?.status === 'completed' || expired;

  useEffect(() => {
    if (!active || finished) return;
    const clock = setInterval(() => setNow(Date.now()), 1000);
    const controller = new AbortController();
    let reading = false;
    const poll = setInterval(() => {
      if (reading) return;
      reading = true;
      void readVerification(identity, active.sessionId, AbortSignal.any([controller.signal, AbortSignal.timeout(8000)]))
        .then(value => { if (!controller.signal.aborted && value.status !== 'pending') { setResult(value); changed.current(); } })
        .catch(() => { /* the next tick retries; the list keeps its own errors */ })
        .finally(() => { reading = false; });
    }, 3000);
    return () => { controller.abort(); clearInterval(clock); clearInterval(poll); };
  }, [active, finished]);

  async function start() {
    setBusy(true); setError(''); setNeedsStepUp(false); setResult(null); setActive(null);
    try {
      const started = await startVerification(identity, AbortSignal.timeout(12000));
      const image = await QRCode.toDataURL(started.launchUri, { width: 560, margin: 4 });
      setNow(Date.now()); setActive({ ...started, image }); changed.current();
    } catch (cause) {
      setNeedsStepUp(cause instanceof AuthError && cause.code === 'step_up_required');
      setError(startError(cause));
    } finally { setBusy(false); }
  }

  const seconds = active ? Math.max(0, Math.floor((Date.parse(active.expiresAt) - now) / 1000)) : 0;
  return <section className="dashboard-activity verification-new" aria-labelledby="new-verification-title">
    <h2 id="new-verification-title">Verificar una credencial</h2>
    <div className="actions">
      <button disabled={busy} onClick={() => void start()}>{busy ? 'Creando…' : 'Nueva verificación'}</button>
      {needsStepUp && <button onClick={onStepUp}>Verificar identidad</button>}
      {active && <button onClick={() => { setActive(null); setResult(null); }}>Cerrar</button>}
    </div>
    {error && <p role="alert">{error}</p>}
    {active && result?.status === 'completed' && <p role="status" className="verification-result" data-result={result.result}>
      <strong>Presentación {resultNames[result.result!].toLowerCase()}</strong>
      {result.codes?.length ? ` · ${result.codes.join(', ')}` : ''}
      <span>Es el resultado técnico de las comprobaciones. No consulta revocación ni autoriza el ingreso de una persona a un evento.</span>
    </p>}
    {active && result?.status !== 'completed' && (expired || result?.status === 'expired'
      ? <p role="status">La solicitud caducó. Crea una nueva verificación.</p>
      : <div className="verification-qr">
        <img src={active.image} alt="Código QR de la solicitud de verificación" width={280} height={280} />
        <p>En la wallet: <strong>Presentar credencial → Escanear QR</strong>.</p>
        <p role="timer">Vence en {Math.floor(seconds / 60)}:{String(seconds % 60).padStart(2, '0')} · esperando respuesta…</p>
      </div>)}
  </section>;
}
