import { AuthError, request } from '../authentication/client';
import type { Identity } from '../authentication/client';

// Read-only view of the tenant's verification sessions (ADR-0033 #9, VER-T11-e).
// Contract: src/platform/contracts/verification-sessions.openapi.json (browser mount).
export type SessionStatus = 'pending' | 'completed' | 'expired';
export type StatusFilter = '' | SessionStatus;
export interface VerificationSession {
  sessionId: string; status: SessionStatus; result?: 'pass' | 'fail'; codes?: string[]; reportDigest?: string;
  createdAt: string; expiresAt: string; completedAt?: string;
}
export interface VerificationPage { items: VerificationSession[]; nextCursor: string | null }

export const statusNames: Record<SessionStatus, string> = { pending: 'Pendiente', completed: 'Completada', expired: 'Caducada' };
export const resultNames = { pass: 'Aprobada', fail: 'Rechazada' } as const;
export const filterNames: Record<StatusFilter, string> = { '': 'Todas', pending: 'Pendientes', completed: 'Completadas', expired: 'Caducadas' };

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const digest = /^sha256:[0-9a-f]{64}$/;
const timestamp = (v: unknown): v is string => typeof v === 'string' && v.endsWith('Z') && Number.isFinite(Date.parse(v));

// The response is checked field by field: anything outside the contract is
// treated as a failed read rather than rendered.
export function validSession(s: unknown): s is VerificationSession {
  if (!s || typeof s !== 'object') return false;
  const v = s as Record<string, unknown>;
  const allowed = ['sessionId', 'status', 'result', 'codes', 'reportDigest', 'createdAt', 'expiresAt', 'completedAt'];
  if (!Object.keys(v).every(key => allowed.includes(key))) return false;
  if (typeof v.sessionId !== 'string' || !uuid.test(v.sessionId) || !['pending', 'completed', 'expired'].includes(v.status as string) ||
    !timestamp(v.createdAt) || !timestamp(v.expiresAt)) return false;
  if (v.status === 'completed') {
    return ['pass', 'fail'].includes(v.result as string) && typeof v.reportDigest === 'string' && digest.test(v.reportDigest) && timestamp(v.completedAt) &&
      (v.codes === undefined || (Array.isArray(v.codes) && v.codes.length <= 32 && v.codes.every(code => typeof code === 'string' && code.length <= 128)));
  }
  return v.result === undefined && v.codes === undefined && v.reportDigest === undefined && v.completedAt === undefined;
}

export function validPage(value: unknown, status: StatusFilter, limit: number): value is VerificationPage {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  if (Object.keys(v).some(key => key !== 'items' && key !== 'nextCursor')) return false;
  if (!Array.isArray(v.items) || v.items.length > limit || !v.items.every(validSession)) return false;
  if (!(v.nextCursor === null || (typeof v.nextCursor === 'string' && v.nextCursor.length >= 32 && v.nextCursor.length <= 2048))) return false;
  return !status || v.items.every(item => (item as VerificationSession).status === status);
}

export async function readVerificationPage(identity: Identity, status: StatusFilter, cursor: string, signal: AbortSignal, limit = 25): Promise<VerificationPage> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (status) params.set('status', status);
  if (cursor) params.set('cursor', cursor);
  const value: unknown = await (await request(`/console/api/tenants/${encodeURIComponent(identity.activeTenantId!)}/verification-sessions?${params}`, signal)).json();
  if (!validPage(value, status, limit)) throw new AuthError(503, 'invalid_response');
  return value;
}

export interface StartedVerification { sessionId: string; launchUri: string; expiresAt: string }

const base = (identity: Identity) => `/console/api/tenants/${encodeURIComponent(identity.activeTenantId!)}/verification-sessions`;

// Starting needs CSRF and recent MFA; the server decides both (ADR-0037).
export async function startVerification(identity: Identity, signal: AbortSignal): Promise<StartedVerification> {
  const value: any = await (await request(base(identity), signal, identity.csrfToken, { ttlSeconds: 300 }, { method: 'POST' })).json();
  if (!value || typeof value.sessionId !== 'string' || !uuid.test(value.sessionId) || typeof value.launchUri !== 'string' ||
    !value.launchUri.startsWith('openid4vp://') || !timestamp(value.expiresAt)) throw new AuthError(503, 'invalid_response');
  return value as StartedVerification;
}

export async function readVerification(identity: Identity, sessionId: string, signal: AbortSignal): Promise<VerificationSession> {
  const value: unknown = await (await request(`${base(identity)}/${encodeURIComponent(sessionId)}`, signal)).json();
  if (!validSession(value) || value.sessionId !== sessionId) throw new AuthError(503, 'invalid_response');
  return value;
}

export function message(cause: unknown): string {
  if (cause instanceof AuthError) {
    if (cause.status === 403 || cause.status === 404) return 'Tu acceso cambió. Se ha comprobado el contexto; revisa la organización y tus permisos antes de reintentar.';
    if (cause.status === 422 || cause.status === 400) return 'La página ha caducado o el filtro no es válido. Reinicia la lista para consultar los datos actuales.';
  }
  return 'No pudimos cargar las verificaciones. Comprueba tu conexión y reintenta.';
}
