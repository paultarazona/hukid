# Guía de integración del validador (para wallet e issuer)

Estado: guía para quienes desarrollan el wallet y el issuer y necesitan usar el validador de HukID (FEAT-004). Describe lo que el código acepta y responde hoy, leído de `src/platform/internal/verification`, `internal/oid4vp`, `internal/adapters/oid4vphttp` y [la OpenAPI](../../src/platform/contracts/verification-sessions.openapi.json). Es laboratorio y staging: producción sigue en NO-GO. Las referencias normativas son el [perfil](hukid-profile.md) (§9 y §10) y el [contrato del núcleo](credential-verification-contract.md), que fija los códigos de resultado.

## 1. Qué es y dónde está

El validador es un módulo del binario de HukID (ADR-0031) que, por tenant, inicia una solicitud OpenID4VP, recibe la respuesta del wallet y emite un resultado (`pass` o `fail` y códigos). No guarda la credencial, la VP ni los claims: guarda el digest y los códigos.

| Dato (staging) | Valor |
| --- | --- |
| Base pública | `https://hukid.zentrycore.com` |
| Request object del wallet | `GET /oid4vp/request/{state}` |
| Respuesta del wallet | `POST /oid4vp/response` |
| `client_id` del verifier | `x509_san_dns:hukid.zentrycore.com` |
| `response_uri` | `https://hukid.zentrycore.com/oid4vp/response` |
| Sesiones (operador, Bearer) | `/v1/operator/tenants/{tenantId}/verification-sessions` |

Todas las respuestas llevan `Cache-Control: no-store`. Los errores son JSON `{"error":"<código>"}` genéricos a propósito: la causa no se expone.

## 2. Flujo

1. El operador del tenant inicia una sesión (§5) y recibe un `launchUri`.
2. El wallet abre el `launchUri`: `openid4vp://authorize?client_id=…&request_uri=https://…/oid4vp/request/{state}&request_uri_method=get`.
3. El wallet hace `GET request_uri` y recibe el request object firmado.
4. El wallet arma la VP, la cifra y la envía a `response_uri`.
5. El validador responde `200 {}` si la respuesta se procesó (el resultado, válido o inválido, **no** va en esta respuesta) o un error genérico.
6. El operador lee el resultado por `GET …/verification-sessions/{sessionId}`.

La sesión dura 5 minutos por defecto (60 s a 15 min a petición del operador) y se consume una sola vez.

## 3. Para el wallet

### 3.1 Request object

`GET /oid4vp/request/{state}` sin query. Responde `200` con `Content-Type: application/oauth-authz-req+jwt`; `404 invalid_request_uri` si el `state` no existe, expiró o ya se usó.

- **Header:** `alg` `ES256`, `typ` `oauth-authz-req+jwt`, `kid` de la clave de firma custodiada del tenant. `x5c` **no se incluye todavía** (ver §7).
- **Claims:** `iss` y `client_id` (el `client_id` del verifier), `aud` `https://self-issued.me/v2`, `response_type` `vp_token`, `response_mode` `direct_post.jwt`, `response_uri` (exacta), `nonce`, `state`, `iat`, `exp`, `dcql_query` y `client_metadata`.
- **`dcql_query`:** una consulta de credencial con `id`, `format` `application/vc+jwt` y `meta` vacío.
- **`client_metadata`:** `jwks.keys[0]` es la JWK de cifrado de la respuesta (EC P-256, `use` `enc`, `alg` `ECDH-ES`, con `kid`) y `encrypted_response_enc_values_supported` es `["A256GCM"]`. Esa clave **solo cifra la respuesta**: no sirve para verificar la firma del request object.

La clave pública para verificar el request object se obtiene fuera de banda: la devuelve `verifierctl provision-key` y queda en la base. Hoy la `kid` activa de staging es `a806f17ef7a79ce50a55c0dee77baf6b`. Si la cambia una rotación, hay que pedir la nueva.

### 3.2 La presentación (VP)

- **Formato:** `application/vp+jwt` compacta, hasta 64 KiB, con hasta 8 credenciales.
- **Header:** `alg` `ES256`, `typ` `vp+jwt` y la clave pública del holder en `jwk`. La firma de la VP se verifica con esa clave.
- **Contexto:** `https://schemas.hukid.pe/contexts/presentation/v1`.
- **`aud`:** el `client_id` del request, tal cual (incluido el prefijo `x509_san_dns:`).
- **`nonce`:** el del request. **`state`** de la respuesta: el del request.
- **Credenciales:** cada una `application/vc+jwt` y con `cnf.jkt` igual al thumbprint RFC 7638 de la clave que firmó la VP (§4).

### 3.3 La respuesta

`POST /oid4vp/response` con `Content-Type: application/x-www-form-urlencoded` y un único campo `response`.

- **Cifrado:** JWE compacto con `alg` `ECDH-ES`, `enc` `A256GCM`, `kid` igual al de la JWK de `client_metadata` y sin `zip`. Hasta 192 KiB.
- **Contenido descifrado:** `{"vp_token":{"<id de la consulta>":["<VP>"]},"state":"<state>"}`. Exactamente una consulta con exactamente una presentación; JSON sin miembros extra.

| Respuesta | Causa probable |
| --- | --- |
| `200 {}` | Procesada. Consulte el resultado por la API del operador. |
| `400 invalid_request` | Sesión desconocida o expirada, JWE inválido, forma de `vp_token` incorrecta o `kid` desconocido. No se distingue la causa. |
| `415 invalid_request` | Falta `application/x-www-form-urlencoded`. |
| `405 invalid_request` | No es `POST`. |
| `500 server_error` | Fallo de una dependencia. La solicitud no se pierde en silencio. |

Una respuesta con firma de holder inválida **no consume** la solicitud: se puede reintentar dentro del TTL. Una respuesta con firma válida la consume, aunque el resultado sea `fail`; otra respuesta a la misma solicitud da `request.replayed`.

## 4. Para el issuer

El validador solo acepta credenciales `application/vc+jwt` que cumplan el perfil. Hasta 16 KiB.

**Header**
- `alg` `ES256`, `typ` `vc+jwt`, `kid` obligatorio.
- Sin `jku`, `jwk`, `x5u` ni `x5c`: la credencial no trae su propia clave (`key.untrusted_header`).

**Payload (VCDM 2.0 directo)**
- Sin contenedor `vc`. Sin `iss`, `nbf` ni `sub`: duplican `issuer`, `validFrom` y el sujeto (`format.payload.duplicate_claim`).
- `@context`: el primero es `https://www.w3.org/ns/credentials/v2`. Sin contextos en línea. Otros contextos solo si están en la lista permitida del verifier (hoy, solo el base).
- `type` incluye `VerifiableCredential`. `issuer` es una cadena no vacía.
- `validFrom` y `validUntil` en RFC 3339, con `validFrom` anterior a `validUntil`. La ventana es `[validFrom, validUntil)` con tolerancia de reloj de 1 minuto.
- `cnf.jkt`: thumbprint RFC 7638 de la clave del holder. Sin él: `binding.missing_cnf`.
- JSON estricto: sin miembros duplicados, profundidad máxima 8.

**`credentialStatus` y `credentialSchema`: hoy invalidan la credencial.** Su comprobación no está implementada. Si la credencial declara cualquiera de los dos, ese criterio sale `skipped.not_implemented` **requerido** y el resultado es `fail`. Si no los declara, se omiten como opcionales. Mientras no existan las listas de status (VER-T09) ni el Definition Registry (VER-T13), una credencial que deba pasar la validación no puede declararlos. Esto es una limitación temporal, no un diseño final: cuando existan, la comprobación se activa y las credenciales ya emitidas con esos miembros pasarán a validarse de verdad.

### 4.1 Cómo publica el issuer su clave

**Hoy** (sin resolución por JWKS, VER-T12 sin integrar): el validador solo conoce los emisores listados en `deploy/staging/issuer-keys.json`, con este formato por clave:

```json
{ "issuer": "<identificador exacto del issuer>", "kid": "<kid>", "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } }
```

Solo claves públicas P-256, hasta 32 y 64 KiB en total. Para que su issuer quede reconocido, mande esa fila (nunca la clave privada) al dueño del validador, que la añade al archivo y redespliega. El `issuer` de la credencial debe coincidir exactamente con el de la fila, y el `kid` del header con el de la fila (`key.unknown_kid` y `key.issuer_mismatch` si no).

**Más adelante** (VER-T12): el validador obtendrá el JWKS por HTTPS solo del host del propio issuer, sin seguir redirects a otro origen y sin usar `jku`. Requisitos del lado del issuer, para que no haya que rehacer nada:
- JWKS publicado en un host cuyo nombre coincida con el `issuer`.
- Una clave retirada **sigue publicada** mientras haya credenciales vigentes firmadas con ella: el validador espera poder resolverla.
- Rotación: clave nueva con `kid` nuevo; no reutilizar `kid`.

**Confianza.** Que una clave esté en la lista permite verificar la firma, no decide si el verifier "confía" en ese issuer. Esa decisión es una política aparte (`TrustPolicy`) y, según el montaje actual de staging, no hay ninguna configurada: el reporte no lleva `trust`.

## 5. API del operador (quien integra el backend)

Contrato completo en la [OpenAPI](../../src/platform/contracts/verification-sessions.openapi.json) (borrador 0.1.0). Autenticación `Authorization: Bearer` del operador; las capacidades salen de su membresía local, no de los roles del token.

| Operación | Ruta | Capacidad | Notas |
| --- | --- | --- | --- |
| Iniciar | `POST …/verification-sessions` | `verification:start` | MFA reciente obligatoria. Cuerpo opcional `{"ttlSeconds":60–900}`. `201` con `sessionId`, `launchUri`, `expiresAt`. |
| Leer una | `GET …/verification-sessions/{sessionId}` | `verification:read` | `status`: `pending`, `completed` o `expired`. |
| Listar | `GET …/verification-sessions` | `verification:read` | Más recientes primero, cursor, `limit` 1–100, filtro `status`. |

Resultado de una sesión `completed`: `result` (`pass` o `fail`), `codes` (códigos del conjunto cerrado, `CodesVersion` 2) y `reportDigest` (`sha256:…`). Nunca la credencial, la VP, los claims, el nonce ni el state. No hay webhook: el resultado se consulta por polling.

Los códigos y su significado están en el [contrato del núcleo](credential-verification-contract.md#códigos-versión-2). Los que más verá un integrador: `signature.invalid`, `binding.mismatch`, `binding.missing_cnf`, `request.audience_mismatch`, `request.nonce_mismatch`, `request.state_mismatch`, `request.replayed`, `key.unknown_kid`, `validity.expired` y `skipped.not_implemented`.

## 6. Cómo probar contra staging

1. Mande al dueño del validador la fila de su issuer (§4.1) y pida que quede en `issuer-keys.json`. Pida también la clave pública de verificación del request object.
2. Pida una sesión (o un `launchUri` de prueba) al operador del tenant.
3. Desde el wallet: `GET` del `request_uri`, verifique la firma, arme la VP (§3.2), cífrela (§3.3) y haga el `POST`.
4. Compruebe el resultado en la lista de Verificaciones de la consola (`https://hukid.zentrycore.com`) o por la API del operador.

## 7. Lo que todavía no existe

- **Certificado `x5c`:** el request object no lleva cadena de certificado. El `client_id` usa el prefijo `x509_san_dns`, así que un wallet que exija validar esa cadena lo rechazará. Pendiente de una decisión del owner (ADR-0034, perfil §12). Un wallet de prueba debe aceptar, por ahora, el request object verificándolo con la clave pública obtenida fuera de banda.
- **Status y schema** (VER-T09, VER-T13): ver §4.
- **JWKS por HTTPS** (VER-T12): ver §4.1.
- **Interoperabilidad con un wallet externo:** no está probada. Esta guía se contrasta con el primer wallet real, y lo que no coincida se corrige aquí.
- **Autoservicio:** añadir un issuer o un tenant requiere intervención del dueño del validador.
- **Producción:** NO-GO. Los valores de §3 y §4 (tamaños, TTL, tolerancia de reloj) son propuestas del laboratorio, no valores aprobados.
