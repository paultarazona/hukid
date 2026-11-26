# Verificación de punta a punta de staging

Checklist ejecutable contra `https://hukid.zentrycore.com`. Separa lo que ya prueban los tests de Go en CI (contra una base y un IdP desechables, no contra staging) de lo que solo se puede comprobar a mano en staging.

**Estado:** esta lista no se ha ejecutado contra staging. Lo marcado "CI" es lo que existe y pasa en el gate; lo marcado "Manual" es un procedimiento propuesto y no probado.

## Issuer OID4VCI (overlay preparado, despliegue pendiente)

El repo contiene [`compose.issuer.yaml`](../../deploy/staging/compose.issuer.yaml), que agrega el runtime aislado del issuer y los workers optativos, y [`Caddyfile`](../../deploy/staging/Caddyfile), que enruta sus rutas al API. Estos cambios no han sido aplicados al Dokploy ni probados contra el host.

| Verificación | Criterio | Evidencia requerida en staging |
| --- | --- | --- |
| API + overlay | `api` queda healthy con `HUKID_ENV=staging`, HTTPS en auth/public URL, login `issuance` y `HUKID_ISSUANCE_CLAIMS_KEY_CIPHERTEXT` válido. | `docker compose -f compose.yaml -f compose.issuer.yaml ps`; logs sin credenciales; endpoint `/healthz` responde 204. |
| Rutas y descubrimiento | Caddy reenvía authorization-server metadata, metadata/JWKS issuer, OAuth token, endpoints de oferta/nonce/credential/deferred, status/schema/context y `/v1/*` sin devolver el SPA. | `curl -i https://hukid.zentrycore.com/.well-known/oauth-authorization-server`; tras provisionar un issuer, consultar `/{slug}/.well-known/openid-credential-issuer` y `/{slug}/.well-known/jwks.json`; una ruta desconocida bajo `/v1/` no debe ser `index.html`. |
| Vault Transit | El API envuelve/usa claves transit con token de alcance mínimo; la DEK envuelta está asociada a `HUKID_ISSUANCE_CLAIMS_KEY_VERSION`. | Revisión de Vault audit + recorrido sintético de definición/llave; nunca copiar el token o DEK en logs. |
| Worker diferido | Worker inicia solo con tenant piloto válido y completa una emisión diferida, tomando lock tenant-scoped. | Activar perfil `issuer-workers`; crear solicitud diferida de prueba, observar `fulfilled=1` y polling de credencial lista. |
| Worker retención | TTL de 168h ratificado por owner, tenant-scoped y sin afectar material no vencido. | Revisar métricas/logs redacted y auditar `issuance.retention_purged`; prueba de staging con material de prueba vencido. |
| TLS PostgreSQL | API y workers usan `sslmode=verify-full` y CA montada desde archivo host mediante Compose secret. | Confirmar con el proveedor la CA y un hostname resoluble con SAN coincidente; configurar `HUKID_POSTGRES_CA_FILE` (ruta absoluta) y `HUKID_STAGING_DB_HOST`. |

No se considera deploy cerrado hasta aportar evidencia fechada de estas comprobaciones y confirmar que Dokploy está usando ambos compose files.

## Cómo leer la columna "Automatizado"

- **CI (Go):** test de integración en `src/platform/internal/adapters/postgres/`, que el gate `auth-lab` ejecuta con PostgreSQL y OIDC desechables (`npm run test:postgres`). Prueban el código, **no** la configuración de staging.
- **CI (navegador):** recorrido Playwright en `tests/browser/` contra el stack desechable.
- **Local con credenciales reales:** `tests/browser/keycloak.py` (14 etapas con Keycloak y TOTP reales). No corre en CI ni contra staging: apunta a un Keycloak y una base locales.
- **Manual en staging:** hay que hacerlo con tu sesión real.

## 1. Precondición 412 (revisión obsoleta)

| | |
| --- | --- |
| Esperado | Una mutación con `If-Match` de una revisión vieja responde **412**; sin `If-Match`, **428**; con ETag débil o malformado, **400**. |
| CI (Go) | `TestLoginHTTPWithRealOIDCAndPostgres` (HTTP: 428, 400, 412 y 200 con el ETag correcto sobre la revocación de invitaciones y el cambio de membresías); `TestMembershipLifecycleETagReplayAndHistory`. |
| CI (navegador) | `members.py`: "412 draft recovery" (el borrador sobrevive a un 412). |
| Manual en staging | Abre **Miembros** en dos pestañas. En la primera cambia el rol de un miembro y guarda. En la segunda, sin recargar, cambia el mismo miembro y guarda: debe mostrarse el aviso de revisión obsoleta y conservarse tu borrador, sin aplicar el cambio. |

## 2. Último administrador

| | |
| --- | --- |
| Esperado | Revocar o suspender al único administrador activo responde **409** `last_admin_required`; el tenant nunca queda sin administrador, tampoco con dos intentos concurrentes. |
| CI (Go) | `TestMembershipConcurrentLastAdministrators`, `TestMembersTenantLockSerializesLastAdminAndReleases` (nivel base de datos, con concurrencia). |
| Local con credenciales reales | `keycloak.py`, etapa `last_administrator_protected` (el 409 por HTTP con sesión real). No hay un test de Go que compruebe el 409 HTTP. |
| Manual en staging | **Riesgo:** la regla la aplica el código, no la base. Si fallara, quedarías sin administrador y la recuperación sería con SQL (`bootstrap` no reactiva una identidad existente). Hazlo solo cuando exista un segundo `tenant_admin`; si no, confía en CI y en la etapa local. Con un único administrador, intenta suspenderte a ti mismo en **Miembros**: debe rechazarse con el mensaje de administrador requerido. |

## 3. Idempotencia

| | |
| --- | --- |
| Esperado | Repetir una creación con la misma `Idempotency-Key` y el mismo cuerpo devuelve la misma respuesta sin duplicar; con la misma clave y otro cuerpo, **409**. |
| CI (Go) | `TestLoginHTTPWithRealOIDCAndPostgres` (201 repetido; 409 con cuerpo distinto), `TestMembersHistoryIdempotencyAndRetentionStorage`, `TestInvitationCommandsReplayReplacementRevocationAndReauthorization`. |
| Local con credenciales reales | `keycloak.py`, etapa `invitation_create_replay_revoke`. |
| Manual en staging | Crea una invitación desde **Invitaciones**. En las herramientas del navegador (Red), copia esa petición `POST` como `fetch` y ejecútala otra vez en la consola, sin cambiar nada: debe devolver el mismo cuerpo y **no** aparecer una segunda invitación. Cambia el correo y repite: **409**. |

## 4. Invitaciones

| | |
| --- | --- |
| Esperado | Crear, reemplazar, revocar y aceptar una invitación; el código se usa una sola vez; las caducadas o revocadas no se aceptan; reingreso con nuevo ciclo de vida. |
| CI (Go) | `TestAcceptanceIdentityOneUseAndLiveReplay`, `TestAcceptanceReentryAndOldInvitationCutoff`, `TestAcceptanceConcurrentAndAtomicRollback`, `TestAcceptanceExpiredRevokedExistingAndInactive`, `TestInvitationAtomicEvidenceAndConcurrentCommands`, `TestInvitationDeliveryFailureRetryCrashDedupAndRetention`. |
| CI (navegador) | `members.py`: invitación real, aceptación con una segunda identidad, roles, suspensión y revocación. |
| Manual en staging | **Limitado:** staging usa la política `*.test.json` con entrega `synthetic-only` ([ADR-0029](../decisions/ADR-0029.md)), así que **no sale ningún correo**. Se puede comprobar crear, revocar y listar. La aceptación completa necesita el código de la invitación y una segunda identidad con TOTP en Keycloak: sin SMTP real no está probada en staging. |

## 5. Sesión

| | |
| --- | --- |
| Esperado | Login con contraseña y TOTP crea la sesión; `refresh` rota la cookie; `logout` revoca la cookie anterior; CSRF y `Origin` ajeno se rechazan con 403; otro tenant da 403 o 404; la cookie es `__Host-hukid_session`, `Secure`, `HttpOnly`, `SameSite=Lax`. |
| CI (Go) | `TestLoginHTTPWithRealOIDCAndPostgres` (401 sin sesión, 403 con `Origin` o CSRF malos), `TestSessionLifecycleConcurrencyLossAndLogout`, `TestRefreshAndStepUpRotationCannotRestoreLostContext`, `TestTenantRLSAndPoolReuseOnCommitRollbackAndPanic`. |
| Local con credenciales reales | `keycloak.py`: `password_and_real_otp_create_bff_session`, `csrf_and_origin_denied`, `real_refresh_rotates_cookie`, `real_step_up`, `members_and_tenant_isolation`, `logout_revokes_previous_cookie_and_requires_credentials`, `signed_token_profile_and_replay`. |
| Manual en staging | (a) Entra con `paul.operador`: contraseña y TOTP; debe cargar la consola. (b) En Application > Cookies del navegador comprueba el nombre y las banderas. (c) Usa **Renovar sesión** y comprueba que el valor de la cookie cambia. (d) Cierra sesión y, desde otra pestaña con la sesión anterior, recarga: debe pedir login. (e) Copia como cURL una petición `/console/api/me` hecha antes del logout y reenvíala: debe dar **401**. No pegues el valor de la cookie en el chat ni en un archivo del repo. |

## Qué sale en CI hoy y qué no

- **Corre en CI:** todos los tests de Go de arriba (gate `auth-lab`, Windows) y los recorridos de `authentication.py`, `members.py` y `dashboard.py`.
- **No corre en CI:** `keycloak.py` (propuesta pendiente de añadir `npm run test:keycloak` al workflow) y cualquier comprobación contra staging.
- **Hueco:** ningún test comprueba el 409 `last_admin_required` por HTTP en CI; solo la etapa local con credenciales reales y los tests de base de datos.
