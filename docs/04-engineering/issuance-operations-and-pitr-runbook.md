# Issuance Operations, Retention, DLQ Replay, Tunnel & PITR Runbook

Este runbook documenta la operación productiva del plano de emisión de HukID: retención / crypto-shredding (`HK-053`), métricas operativas y replay de DLQ (`HK-054`), backup/restore PITR y verificación de consistencia con Vault Transit (`HK-055`), comandos administrativos de status (`ISS-T06` / `HK-050`) y exposición por túnel HTTPS real (`HUKID_ISSUANCE_PUBLIC_URL`).

## 1. Objetivos RPO / RTO

| Componente | RPO objetivo | RTO objetivo | Mecanismo principal |
| --- | --- | --- | --- |
| PostgreSQL (`hukid`: schemas `tenancy`, `issuance`, `status`, `audit`, `verification`) | <= 5 minutos | <= 30 minutos | Base backup diario + archivado continuo de WAL / PITR. |
| HashiCorp Vault Transit (KEK de claims y claves ECDSA P-256 de issuers) | 0 (sin pérdida) | <= 15 minutos | Raft snapshots / almacenamiento replicado de Vault; `kms_key_ref` en DB debe concordar 1:1 con keys en Transit. |
| Status Lists firmadas y Bitstrings publicados | <= 5 minutos | <= 15 minutos | Persistidos en `status.status_lists` y re-publicables ante transición o rotación de clave. |

## 2. Túnel HTTPS real para Wallet / OID4VCI (`HUKID_ISSUANCE_PUBLIC_URL`)

Por defecto el API utiliza `https://issuer.hukid.pe/` como prefijo público para generar y validar `issuerUri`, `credential_issuer`, `credential_offer_uri`, `nonce_endpoint`, `credential_endpoint`, `deferred_credential_endpoint`, JWKS y Status Lists. Para pruebas en vivo con la Wallet Flutter externa o túneles (`cloudflared`, `ngrok`):

```bash
export HUKID_ISSUANCE_PUBLIC_URL="https://hukid-lab.trycloudflare.com/"
export HUKID_ISSUANCE_AUTH_SERVER="https://hukid-lab.trycloudflare.com"
npm run env
```

Requisitos de validación aplicados al arranque (`cmd/api/runtime_services.go` e `internal/issuance/signer.go`):

- Debe usar esquema `https://` (sin credenciales de usuario, query string ni fragmento).
- La tabla `issuance.issuers` acepta URIs `^https?://[^/?#]+/.+` terminadas en `/{slug}`, permitiendo coexistencia con datos existentes o emisores creados bajo URL de túnel.
- Recuerda crear o apuntar los emisores y tokens tras fijar `HUKID_ISSUANCE_PUBLIC_URL` para que el campo `iss`, el `aud` del `jwt` proof y los endpoints de `.well-known/openid-credential-issuer` coincidan con el host público del túnel.

## 3. Cambios de estado por operador (`ISS-T06` / `HK-050`)

Los administradores con capability `issuers:manage` y MFA reciente (`step-up`) pueden suspender, reactivar o revocar credenciales emitidas desde `#credenciales` o vía Private API / BFF:

- `POST /v1/operator/tenants/{tenantId}/credentials/{credentialId}/suspend`
- `POST /v1/operator/tenants/{tenantId}/credentials/{credentialId}/reactivate`
- `POST /v1/operator/tenants/{tenantId}/credentials/{credentialId}/revoke`

Reglas operativas:

- Todas las mutaciones exigen cabecera `Idempotency-Key` válida.
- `suspend` y `revoke` requieren `reasonCode` sin espacios (`operator_request`, `security_response`, `holder_request`, `data_correction`).
- `revoke` es terminal e irreversible; intentar `reactivate` o `suspend` después devuelve `409 Conflict` (`invalid_state_transition`).
- Toda transición vuelve a firmar y publicar la Bitstring Status List en PostgreSQL y registra evento de auditoría (`credential.suspended`, `credential.reactivated`, `credential.revoked`) atribuido al actor operador.

## 4. Retención y Crypto-Shredding (`HK-053`)

La limpieza periódica expira ofertas vencidas (`ready` -> `expired`) y ejecuta crypto-shredding (`claims_ciphertext = '\x'`, `source_reference = ''`, `vc_ciphertext = '\x'`) sobre solicitudes terminales (`issued`, `cancelled`, `failed`) y transacciones diferidas ya entregadas cuya antigüedad supere la ventana de retención.

Ejecución manual (one-shot) o periódica desde `cmd/worker`:

```bash
go run ./cmd/worker retention <tenant-id> --retention-ttl=168h --limit=500
# o como daemon acotado:
go run ./cmd/worker retention <tenant-id> --retention-ttl=168h --limit=500 --interval=10m
```

Variables requeridas: las mismas variables aisladas del worker de emisión (`HUKID_ENV`, `HUKID_ISSUANCE_DATABASE_URL`, `HUKID_ISSUANCE_AUTH_SERVER`, `HUKID_ISSUANCE_CLAIMS_KEY_VERSION`, clave/ciphertext de claims y `HUKID_VAULT_*`). El worker usa advisory lock tenant-scoped (`hukid/retention-worker/v1`) para evitar carreras entre réplicas HA. Si purga o tritura al menos un registro, emite evento de auditoría `issuance.retention_purged`.

## 5. Métricas operativas y Replay de DLQ (`HK-054`)

Consulta de contadores en vivo por tenant (requiere capability `issuance:read`):

```http
GET /v1/operator/tenants/{tenantId}/issuance-metrics
```

Devuelve contadores redacted (sin PII ni claims): `activeIssuers`, `publishedDefinitions`, `preparedRequests`, `deferredPending`, `deferredFailedDlq`, `issuedCredentials`, `suspendedCredentials`, `revokedCredentials`.

Cuando `deferredFailedDlq > 0`, tras resolver la causa raíz (por ejemplo disponibilidad de Vault Transit o conectividad KMS), un operador con `issuers:manage`, MFA reciente e `Idempotency-Key` puede reencolar la solicitud fallida para que el worker diferido la firme en el siguiente ciclo:

```http
POST /v1/operator/tenants/{tenantId}/issuance-requests/{requestId}/replay-dlq
Idempotency-Key: replay-dlq-req-0001
```

Solo se reencolan solicitudes en estado `failed` con transacción diferida en `failed`; en caso contrario responde `409 invalid_state_transition`. Cada reencolado exitoso registra auditoría `issuance.deferred_replayed`.

## 6. Procedimiento y Drill de Backup / Restore PITR (`HK-055`)

### 6.1 Toma de snapshot y verificación previa

1. Registrar `pg_current_wal_lsn()` en la instancia primaria y tomar snapshot coordinado de PostgreSQL + snapshot Raft de Vault antes de ventanas críticas (cambios de esquema o rotación masiva).
2. Confirmar que el archivado WAL está activo (`archive_mode = on`) y sin rezago de replicación.

### 6.2 Simulación de Restore PITR (Drill reproducible)

1. Provisionar instancia de recuperación aislada sin tráfico externo.
2. Restaurar el último base backup y configurar `recovery_target_time` al instante objetivo.
3. Levantar PostgreSQL en modo promoción y validar migraciones/tablas en los 5 schemas (`tenancy`, `issuance`, `status`, `audit`, `verification`).
4. Verificar consistencia criptográfica entre `issuance.issuer_keys` y Vault Transit:
   - Listar claves activas por tenant/emisor en PostgreSQL (`kid`, `kms_key_ref`, `state`).
   - Consultar Vault Transit (`/v1/transit/keys/{key}` o `vault read`) comprobando que cada `kms_key_ref` activo existe y conserva la clave pública registrada.
   - Ejecutar `GET /v1/operator/tenants/{tenantId}/issuance-metrics` y un ciclo completo de emisión/verificación de prueba (`offer -> token -> nonce -> credential -> verify`).
5. Documentar fecha del drill, tamaño de snapshot, tiempo real de restauración (`RTO` observado) y punto WAL recuperado (`RPO` observado).

## 7. Referencias relacionadas

- [Seguridad y operación de HukID](./hukid-security-and-operations.md)
- [Desarrollo local](./local-development.md)
- [Mapa de pendientes FEAT-005](../features/FEAT-005-issuer-operations/tasks.md)
