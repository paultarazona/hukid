# Avances del Issuer y la Wallet OID4VCI + Siguientes Pasos

Actualizado: 2026-11-20. Estado consolidado de las ramas publicadas en `origin` (`https://github.com/juanrmos/hukid.git`).

## 1. Mapa de ramas y commits en `origin`

| Rama | Commit base | Alcance |
| --- | --- | --- |
| `feat/credential-issuance-mvp` | `455d22e` | Issuer completo (OID4VCI 1.0, Vault Transit, PostgreSQL RLS `0015`–`0018`, credencial canónica `ISS-T07`/`ISS-T08`, Consola `#emisores`/`#definiciones`/`#clientes`/`#solicitudes`/`#credenciales`/`#ajustes`, métricas reales del Dashboard, comandos operator de status `ISS-T06`, prefijo de túnel `HUKID_ISSUANCE_PUBLIC_URL`, `HK-053` retención, `HK-054` métricas/DLQ replay, `HK-055` runbook) + merge con `upstream/develop` hasta `ad22ee2`. |
| `feat/wallet-oid4vci-integration` | `e940d3b` + este reporte | Todo `feat/credential-issuance-mvp` más el scaffold de `deploy/wallet` y `src/wallet/` integrado con cliente real OID4VCI 1.0, criptografía P-256/ES256, Android Keystore, bóveda cifrada AES-256-GCM y deep links `openid-credential-offer://`. |

---

## 2. Resumen de avances completados

### 2.1 Backend del Issuer, OID4VCI, KMS y Workers (`src/platform`)

1. **Superficie pública OID4VCI 1.0 y M2M (`oid4vcihttp` + `internal/issuance`):**
   - Descubrimiento `/{slug}/.well-known/openid-credential-issuer`, `/{slug}/.well-known/jwks.json`, `.well-known/oauth-authorization-server`, `POST /oauth2/token`, `GET /{slug}/offers/{ref}`, `POST /{slug}/nonce`, `POST /{slug}/credential`, `POST /{slug}/deferred_credential`, schemas y Bitstring Status Lists firmadas.
   - Credencial canónica de participación en eventos ([canonical-event-participation-credential.md](../03-design/canonical-event-participation-credential.md), [ADR-0036](../decisions/ADR-0036.md)) validada en E2E (`TestCanonicalEventParticipationEndToEndFlow`).
   - Prefijo público configurable mediante `HUKID_ISSUANCE_PUBLIC_URL` (`SetIssuerPrefix` en `signer.go` y CHECK actualizado en `0015_issuer_foundation.sql`) para exponer el emisor local detrás de túneles HTTPS (`cloudflared` / `ngrok`).
2. **Persistencia PostgreSQL con RLS y KMS Vault Transit:**
   - Migraciones `0015`–`0018` con aislamiento multi-tenant estricto por RLS, cifrado AES-256-GCM de claims/offers en reposo y firma ES256 / unwrap en Vault Transit (`vaultkms`), probado contra Vault real en Docker.
3. **Workers HA y operación (`cmd/worker`, `HK-025`, `HK-053`, `HK-054`, `HK-055`):**
   - `worker deferred <tenant-id>`: procesamiento acotado de transacciones diferidas con advisory lock tenant-scoped.
   - `worker retention <tenant-id>`: expiración de ofertas vencidas, crypto-shredding de claims terminales y VC diferidos no recogidos (`PurgeExpiredMaterial`) y auditoría `issuance.retention_purged`.
   - Métricas operativas redacted (`GET /v1/operator/tenants/{tenantId}/issuance-metrics`) y replay auditado de DLQ (`POST /v1/operator/tenants/{tenantId}/issuance-requests/{requestId}/replay-dlq`).
   - Runbook operativo y de PITR documentado en [issuance-operations-and-pitr-runbook.md](../04-engineering/issuance-operations-and-pitr-runbook.md) y [tasks.md](../features/FEAT-005-issuer-operations/tasks.md).

### 2.2 Consola Web, BFF y Dashboard (`src/console` + `privateapi`)

1. **Lectura y ajustes ([ADR-0035](../decisions/ADR-0035.md)):** capability `issuance:read` habilitada para `tenant_admin` (por tenant) e `issuer_operator` (filtrado por `issuerId`), además de `#ajustes` en solo lectura.
2. **Métricas reales en Dashboard (`#resumen`):** `createdRequests` e `issuedCredentials` consultan PostgreSQL con `GRANT SELECT` por columna y políticas RLS para `hukid_dashboard_runtime`, sin acceso a claims ni secretos.
3. **Comandos operator de status (`#credenciales`, `ISS-T06` / `HK-050`):** `POST .../credentials/{credentialId}/suspend`, `/reactivate` y `/revoke` protegidos por `issuers:manage`, MFA reciente, `Idempotency-Key`, reason codes, re-publicación de Status List y formulario en React.

### 2.3 Wallet Flutter Android conectada al Issuer (`src/wallet` + `deploy/wallet`)

Partiendo del scaffold de `FarisR2/hukid` (`feat/wallet-functional`, commit `4605e81`), se implementó la conexión OID4VCI real sin dependencias externas adicionales:

1. **Criptografía P-256 y JWS en Dart puro (`src/wallet/lib/crypto_p256.dart`):** SHA-256, conversión ASN.1 DER → IEEE P1363 64 bytes (`derToP1363`), thumbprints RFC 7638 (`PublicEcJwk.thumbprint()`), verificación/firma NIST P-256 ES256 y construcción de `openid4vci-proof+jwt`.
2. **Puertos de llaves y bóveda cifrada (`src/wallet/lib/keystore.dart`):** interfaces `HolderKeyStore` y `CredentialVault` con implementaciones en memoria para tests e implementaciones nativas Android vía `MethodChannel`.
3. **Capa nativa Android (`MainActivity.kt` y `AndroidManifest.xml`):**
   - `dev.example.hukid_wallet/keystore`: llaves EC `secp256r1` no exportables en `AndroidKeyStore`.
   - `dev.example.hukid_wallet/vault`: bóveda local cifrada con llave `AES-256-GCM` en `AndroidKeyStore` y escritura atómica (`allowBackup="false"`).
   - `dev.example.hukid_wallet/deeplink`: `intent-filter` para esquema `openid-credential-offer://` y permiso `INTERNET`.
4. **Cliente OID4VCI real y UI (`oid4vci_client.dart`, `issuance.dart`, `main.dart`):**
   - `Oid4vciOfferAdapter`: parsea `openid-credential-offer://?credential_offer_uri=...` (HTTPS obligatorio por defecto; loopback HTTP opt-in con `--dart-define=HUKID_ALLOW_INSECURE_LOOPBACK=true`), resuelve `.well-known/openid-credential-issuer` y `.well-known/oauth-authorization-server`, canjea `pre-authorized_code`, solicita `c_nonce`, firma el proof ES256, procesa emisión inmediata (`200`) y diferida (`202` + `pollDeferred`), verifica la firma del `vc+jwt` contra `/.well-known/jwks.json` y valida `cnf.jkt`.
   - `WalletHome` y `ReceivePage`: contador real de credenciales guardadas, consulta de emisiones diferidas pendientes y flujo con consentimiento explícito.
   - Guía de checks en [src/wallet/README.md](../../src/wallet/README.md) y entorno Docker en [deploy/wallet/Dockerfile](../../deploy/wallet/Dockerfile).

---

## 3. Evidencia de verificación ejecutada

| Suite / Verificación | Resultado | Alcance |
| --- | --- | --- |
| `npm run check` (`check:platform`, `check:console`, `test:auth`, `check:docs`) | **PASS** | 20 paquetes Go + `go vet`, `tsc --noEmit`, 20/20 contratos auth, 163 Markdown / 1,511 enlaces locales (ejecutado sobre el estado final de `feat/wallet-oid4vci-integration`). |
| `npm run build` | **PASS** | Binarios Go + bundle de Consola React (ejecutado al cierre de `feat/credential-issuance-mvp`). |
| `npm run test:postgres` | **PASS** | PostgreSQL 18.6 descartable con RLS (`TestDashboardQueryMeasurement`, `TestIssuanceBackendRetentionMetricsAndReplayDLQ`, etc.). |
| `HUKID_BROWSER_TEST='^TestConsole(Issuance)?Browser$' npm run test:browser` | **PASS** | Smokes autenticados de Consola y Emisión en navegador real (`66.989 s`). |
| `flutter analyze --no-pub` (Docker Flutter 3.50.0) | **PASS** | 0 issues bajo `strict-casts`, `strict-inference` y `strict-raw-types`. |
| `flutter test --no-pub` (Docker Flutter 3.50.0) | **PASS (17/17)** | `crypto_p256_test.dart`, `issuance_test.dart`, `oid4vci_client_test.dart`, `widget_test.dart`. |
| Interop en vivo Go Issuer ↔ Dart Wallet (`oid4vcihttp` + `Oid4vciOfferAdapter`) | **PASS (1/1)** | Emisión inmediata + emisión diferida contra servidor HTTP Go real en loopback (validación de proof ES256 en Go, JWKS ES256 y `cnf.jkt` en Dart). |

**Limitación honesta del entorno actual:** las pruebas nativas en Kotlin (`MainActivity.kt`: `AndroidKeyStore`, `AES/GCM/NoPadding` y `intent-filter`) aún no se compilaron a APK ni se ejecutaron sobre un emulador o dispositivo Android físico.

---

## 4. Siguientes pasos

### Paso 1 — Compilar APK Android y probar en emulador / dispositivo físico
1. Construir la imagen completa con Android SDK 36 (`target: development`) de [deploy/wallet/Dockerfile](../../deploy/wallet/Dockerfile):
   ```sh
   docker build -f deploy/wallet/Dockerfile -t hukid-wallet-dev:local .
   ```
2. Compilar APK de desarrollo (apuntando primero a un túnel HTTPS del API local o con `--dart-define=HUKID_ALLOW_INSECURE_LOOPBACK=true` para emulador vía `10.0.2.2`) y validar en teléfono/emulador:
   - Generación y firma ES256 en `AndroidKeyStore` (`MainActivity.kt`).
   - Persistencia y lectura tras reinicio de la app usando la bóveda `AES-256-GCM`.
   - Apertura automática desde enlaces `openid-credential-offer://`.
   - *(Opcional UX)* Agregar lector QR con cámara en `src/wallet/` para no depender solo de pegar el enlace o usar deep link.

### Paso 2 — Desplegar el Issuer en `staging` (replicando el patrón de `FEAT-004`)
El binario API/worker y los archivos de runtime de staging están en el repo. En este incremento se implementaron las piezas configurables:
1. **Migraciones:** el árbol actual ya contiene `0013_verification_sessions.sql`, `0014_verifier_keys.sql` y las migraciones de issuer `0015`–`0018`; no renumerar `0015`. Comparar `upstream/develop` solo al integrar una actualización nueva.
2. **Proxy web:** completado en [`Caddyfile`](../../deploy/staging/Caddyfile): discovery/JWKS, OID4VCI, OAuth y `/v1/*` se reenvían al API.
3. **Provisioning y secretos:** completado en `staging_provision.go`, `cmd/stagingdb`, [`staging-secrets.mjs`](../../scripts/staging-secrets.mjs) y [`wrap-staging-claims-key.mjs`](../../scripts/wrap-staging-claims-key.mjs); incluye login aislado `issuance` y wrap de DEK sin persistir plaintext.
4. **Runtime y workers:** completado en [`compose.issuer.yaml`](../../deploy/staging/compose.issuer.yaml); el overlay añade configuración de API con PostgreSQL TLS y workers `deferred`/`retention` de perfil optativo.
5. **Operación:** runbooks y checklist actualizados en [staging-architecture.md](./staging-architecture.md), [staging-operations.md](./staging-operations.md) y [staging-verification.md](./staging-verification.md). Aplicar overlay y validar en el host sigue pendiente: hacen falta endpoint/policy/token reales de Vault, tenant piloto y evidencia HTTPS. Este checkout no hizo deploy remoto.

### Paso 3 — Integración externa completa (`Team 4` + Wallet + Verifier)
Consulta el plan detallado de las 5 etapas, incluyendo conciliación de migraciones y compatibilidad de credenciales con el Validador en staging, en [integration-roadmap.md](./integration-roadmap.md).
1. Conectar el **adaptador outbound de Team 4 (Events)** contra `POST /oauth2/token`, `POST /v1/issuance-requests` y `GET /v1/issuance-requests/{id}` (usando un cliente M2M creado desde Consola).
2. Evaluar soporte de **`tx_code` (OID4VCI v0.1)** si el piloto exige segundo factor al canjear la oferta.
3. Parte **OID4VP (presentación hacia el Verifier)** implementada en `src/wallet/` (`crypto_jwe.dart`, `oid4vp_client.dart`, `MainActivity.kt` y `PresentPage` en `main.dart`); resta prueba de extremo a extremo contra el Validador desplegado en staging tras compilar el APK y registrar la llave del emisor en `issuer-keys.json`.

### Paso 4 — Cierre operativo en la nube (`HK-055` y `HK-056`)
1. Ejecutar el **drill PITR real** de PostgreSQL + verificación de consistencia con Vault Transit documentando `RPO` y `RTO` observados.
2. Correr pruebas de carga e interoperabilidad (`HK-056`) sobre el entorno HTTPS desplegado.
