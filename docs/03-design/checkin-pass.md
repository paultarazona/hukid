# Pase de ingreso (check-in)

Estado: **borrador de laboratorio** ([ADR-0038](../decisions/ADR-0038.md)). `{HUKID}` es el origen público del emisor. Fuera de loopback de laboratorio debe usarse HTTPS.

## Flujo

1. La wallet pide un reto: `POST {HUKID}/v1/passes/nonce` → `200 {"nonce","expiresAt"}`.
2. La wallet envía `POST {HUKID}/v1/passes` con `{"presentation":"<vp+jwt>"}`: una sola credencial envuelta, firmada con la clave del titular, `aud={HUKID}/v1/passes` y el nonce. → `201 {"code","expiresAt"}`.
3. La wallet muestra el QR con el texto `hukid-pass://v1?code=<code>`.
4. El **servidor** de la puerta canjea el código (abajo). El navegador de la puerta nunca recibe sus credenciales.

La credencial debe llevar `credentialSubject.recipient.registrationId` y `credentialSubject.event.id`.

| Respuesta del paso 2 | Motivo |
| --- | --- |
| `403 pass_rejected` | Firma, nonce, audiencia, titular, emisor o estado no válidos; no se detalla cuál. |
| `422 pass_not_supported` | Faltan los datos de ingreso. |
| `429 too_many_passes` | Almacén en memoria lleno. |

El nonce dura 60 s. Un intento firmado y bien dirigido lo consume aunque falle después: pedir otro. Un pase nuevo de la misma credencial sustituye al anterior.

## Integración de la puerta

Token: `POST {HUKID}/oauth2/token` (formulario) con `grant_type=client_credentials`, `client_id`, `client_secret` y `scope=pass:verify`. El cliente se registra en la consola con el permiso «Verificar pases de ingreso» y sus emisores. Usar un cliente distinto del de emisión.

Canje: `POST {HUKID}/v1/pass-verifications`, `Authorization: Bearer <token>`:

```json
{ "code": "<code del QR>", "eventId": "<evento de esta puerta>" }
```

Respuesta `200`:

```json
{ "result": "pass", "registrationId": "…", "eventId": "…", "credentialId": "vc_…", "credentialDefinition": "id@versión" }
```

```json
{ "result": "fail", "code": "code_invalid" }
```

| `code` | Significado | ¿Consume el pase? |
| --- | --- | --- |
| `code_invalid` | Inexistente, usado, vencido o de un tenant o emisor no concedido. | — |
| `event_mismatch` | El pase es de otro evento. | No |
| `credential_not_active` | La credencial se suspendió o revocó. | No |

Sólo `pass` consume el código. Sin el scope: `403`. Token ausente o inválido: `401`.

La puerta **debe** además: comprobar que `credentialDefinition` es la que concede el ingreso, que `registrationId` corresponde a una inscripción vigente de `eventId`, y registrar la entrada de forma idempotente. Si la respuesta del canje se pierde, el código ya está usado: pedir al participante un pase nuevo.
