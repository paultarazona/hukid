# Guía de Prueba End-to-End (E2E) — Ecosistema HukID

Esta guía detalla el procedimiento paso a paso para ejecutar y verificar el flujo completo **End-to-End** de credenciales verificables descentralizadas (W3C VCDM 2.0 / OpenID4VC) en HukID.

---

## 1. Arquitectura y Actores del Flujo E2E

El flujo conecta los tres actores del modelo de identidad autosoberana más la plataforma de eventos:

```
┌─────────────────────────┐
│ Plataforma de Eventos   │ 1. Solicitud M2M (POST /v1/issuance-requests)
│ (Sistema externo / Eq4) │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  HUKID ISSUER (Emisor)  │ 2. Genera oferta (openid-credential-offer://)
│ Backend Go + Vault KMS  │    Expone OID4VCI y firma con llave P-256
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│   HUKID WALLET (App)    │ 3. Canjea código, prueba de posesión (proof JWT),
│ Flutter Android Client  │    guarda VC cifrada (AES-GCM) en bóveda local
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ HUKID VERIFIER (Validad)│ 4. Desafío OID4VP (openid4vp://)
│ Backend Go (Staging)    │ 5. Wallet cifra presentación (JWE ECDH-ES A256GCM)
└─────────────────────────┘ 6. Validador descifra, verifica y autoriza (Valid)
```

---

## 2. Inventario de Credenciales y Secretos

| Componente | Clave / Credencial | Propósito | Estándar / Algoritmo |
| --- | --- | --- | --- |
| **Emisor** | `unas-key-1` (privada) | Firma de credenciales emitidas (`vc+jwt`) | ECDSA secp256r1 (ES256) |
| **Emisor** | `claimsKey` (32 bytes) | Cifrado en reposo de claims y ofertas | AES-256-GCM |
| **Emisor** | `cli_events` (secret) | Autenticación M2M del sistema de eventos | OAuth2 `client_credentials` |
| **Billetera** | Par de llaves Holder | Prueba de posesión (*holder binding*) | Android Keystore P-256 / ES256 |
| **Billetera** | Master Key del Baúl | Cifrado de credenciales en SQLite/disco | AES-256-GCM en Keystore |
| **Validador** | `ver-sig-1` (privada) | Firma de solicitudes OID4VP | ECDSA secp256r1 (ES256) |
| **Validador** | Clave de Cifrado ECDH | Receptor de presentaciones cifradas | ECDH-ES + A256GCM JWE |

---

## 3. Modalidad 1: Prueba Automatizada de 3 Vías (Local)

Esta prueba levanta en tiempo de ejecución un servidor Go con TLS que expone simultáneamente el **Emisor OID4VCI** y el **Validador OID4VP**, monta un contenedor Docker con la **Billetera Flutter**, y completa todo el ciclo en ~25 segundos.

### Pasos de Ejecución

1. Asegurar que la imagen Docker del SDK de Flutter esté disponible:
   ```sh
   docker build --target sdk -f deploy/wallet/Dockerfile -t hukid-wallet-sdk:local .
   ```

2. Ejecutar la suite completa de pruebas unitarias y de integración de la Wallet:
   ```sh
   docker run --rm -e PUB_CACHE=/workspace/.pub-cache -v "$PWD/src/wallet:/workspace" -w /workspace hukid-wallet-sdk:local flutter test --no-pub
   ```

3. Ejecutar las pruebas del backend en Go:
   ```sh
   node scripts/platform.mjs check
   ```

### Veredicto Esperado del Validador
El validador de Go emite un dictamen con cuatro comprobaciones obligatorias aprobadas:
```text
Verifier PresentationReport:
  technicalResult = valid
  checks = [
    {Name: format,          Result: pass},
    {Name: signature,       Result: pass},
    {Name: requestBinding,  Result: pass},
    {Name: holderBinding,   Result: pass}
  ]
  credentials = [
    {Name: format,          Result: pass},
    {Name: issuerKey,       Result: pass},
    {Name: signature,       Result: pass},
    {Name: validity,        Result: pass}
  ]
```

---

## 4. Modalidad 2: Prueba Manual Interactiva Paso a Paso

### Paso 1: Solicitud de Emisión M2M desde Plataforma de Eventos

Obtén un token de acceso M2M con el Emisor:

```sh
curl -k -X POST "https://hukid.zentrycore.com/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=cli_events" \
  -d "client_secret=TU_M2M_CLIENT_SECRET" \
  -d "scope=issuance:create issuance:read"
```

Respuesta:
```json
{
  "access_token": "ey...",
  "token_type": "Bearer",
  "expires_in": 300
}
```

Crea la solicitud de emisión de credencial para el asistente:

```sh
curl -k -X POST "https://hukid.zentrycore.com/v1/issuance-requests" \
  -H "Authorization: Bearer ey..." \
  -H "Idempotency-Key: evt-participant-2026-0001" \
  -H "Content-Type: application/json" \
  -d '{
    "issuerId": "iss_unas",
    "credentialDefinition": "unas-pilot@1.0.0",
    "claims": {
      "participantName": "Maria Quispe",
      "eventTitle": "Congreso Cloud UNAS 2026"
    },
    "delivery": {
      "flow": "pre-authorized_code",
      "expiresInSeconds": 300
    }
  }'
```

Respuesta exitosa (`201 Created`):
```json
{
  "id": "req_01j...",
  "status": "pending_issuance",
  "credentialOfferUri": "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fhukid.zentrycore.com%2Funas%2Foffers%2Foff_01j..."
}
```

---

### Paso 2: Generar el Código QR para el Asistente

Convierte el valor de `credentialOfferUri` en un código QR legible (mediante terminal con `qrencode` o una herramienta web):

```sh
qrencode -t ANSIUTF8 "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fhukid.zentrycore.com%2Funas%2Foffers%2Foff_01j..."
```

---

### Paso 3: Reclamar la Credencial en la Billetera (HukID Wallet)

1. Abrir la app **HukID Wallet** en el dispositivo Android.
2. Escanear el código QR o abrir el enlace con el esquema `openid-credential-offer://`.
3. La billetera muestra la pantalla de **Vista Previa de Oferta**:
   - Emisor: `IncubaUNAS` (`https://hukid.zentrycore.com/unas`).
   - Título: `Certificado Piloto UNAS`.
   - Claims: Participante `Maria Quispe`, Evento `Congreso Cloud UNAS 2026`.
4. Pulsar **Aceptar y Guardar**.
5. La app realiza automáticamente:
   - Consulta de metadatos `/.well-known/openid-credential-issuer`.
   - Canje del `pre-authorized_code` por un access token.
   - Generación de llave privada P-256 en Android Keystore y firma del `proof` JWT (`openid4vci-proof+jwt`).
   - Recepción de la credencial W3C `vc+jwt` firmada por el Emisor.
   - Validación criptográfica y persistencia cifrada (AES-256-GCM) en el almacenamiento local.
6. La pantalla de inicio ahora muestra: **1 credencial guardada**.

---

### Paso 4: Iniciar Sesión de Verificación en el Validador

El operador del evento (portería / torniquete) inicia una sesión de verificación OID4VP:

```sh
curl -k -X POST "https://hukid.zentrycore.com/api/v1/verification-sessions" \
  -H "Authorization: Bearer TU_OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "credentialQueryId": "event_cred",
    "acceptedIssuers": ["https://hukid.zentrycore.com/unas"]
  }'
```

El Validador devuelve el enlace de verificación OID4VP:
```text
openid4vp://authorize?client_id=x509_san_dns%3Ahukid.zentrycore.com&request_uri=https%3A%2F%2Fhukid.zentrycore.com%2Foid4vp%2Frequest%2Fsess_xyz123&request_uri_method=get
```

---

### Paso 5: Presentar la Credencial desde la Billetera

1. En la app móvil, pulsar el botón **Presentar credencial**.
2. Escanear el código QR OID4VP o pegar el enlace `openid4vp://authorize?...`.
3. Pulsar **Consultar solicitud**.
4. La billetera descarga el objeto de solicitud autenticado del validador, valida su firma ES256 y extrae la clave pública de cifrado ECDH.
5. Seleccionar la credencial guardada (`Certificado Piloto UNAS`).
6. Pulsar **Presentar**.
7. La billetera:
   - Construye una Presentación Verificable W3C (`application/vp+jwt`) con la credencial envuelta.
   - Firma la presentación con la llave privada del Holder generada en el Keystore.
   - Cifra el token completo en un sobre JWE (`ECDH-ES` + `A256GCM`) usando la llave pública del Validador.
   - Envía el JWE a `POST /oid4vp/response`.
8. Mensaje en pantalla: **«Presentación enviada al validador.»**

---

### Paso 6: Verificación y Dictamen Técnico

El validador descifra el paquete JWE recibido con su llave privada ECDH, valida:
1. La firma del Holder en el `vp+jwt` demostrando posesión legítima de la clave (*holder binding*).
2. La firma del Emisor en el `vc+jwt` contra las claves públicas registradas en `deploy/staging/issuer-keys.json`.
3. El resultado técnico pasa a ser `TechnicalResult: valid`.
4. La pantalla del operador del evento confirma el ingreso: **Acceso Autorizado**.

---

## 5. Perfil de Compatibilidad de Staging

> [!IMPORTANT]
> El validador desplegado por Paul en staging no tiene activada la validación de esquemas (VER-T13) ni listas de revocación (VER-T09). Para que las credenciales emitidas sean compatibles, la definición en el Emisor debe registrarse sin esquemas ni listas de estatus:
> - `publishSchema: false`
> - `statusPurposes: []`
> - `contexts: []`
> Y la clave pública del Emisor debe estar registrada en `deploy/staging/issuer-keys.json`.

---

## 6. Documentos de Referencia

- [integration-roadmap.md](file:///C:/Users/juana/Documentos/8%20Ciclo/Desarrollo%20de%20Aplicaciones%20en%20la%20Nube/hukid/docs/05-delivery/integration-roadmap.md): Hoja de ruta de integración y reconciliación de migraciones.
- [issuer-wallet-progress-and-next-steps.md](file:///C:/Users/juana/Documentos/8%20Ciclo/Desarrollo%20de%20Aplicaciones%20en%20la%20Nube/hukid/docs/05-delivery/issuer-wallet-progress-and-next-steps.md): Estado de avance y plan de trabajo.
