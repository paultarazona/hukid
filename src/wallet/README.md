# HukID Wallet — Android OID4VCI Client

Wallet Android en Flutter conectada al plano de emisión OID4VCI 1.0 de HukID.

## Alcance implementado

- **Descubrimiento y ofertas (`openid-credential-offer://`):** parsea `credential_offer_uri`, valida origen TLS (o loopback explícito con `--dart-define=HUKID_ALLOW_INSECURE_LOOPBACK=true`) y resuelve `/.well-known/openid-credential-issuer` y `/.well-known/oauth-authorization-server`.
- **Llave del titular en Android Keystore (`ES256` / `P-256`):** genera y usa una llave no exportable `secp256r1` en `MainActivity.kt` (`dev.example.hukid_wallet/keystore`) y firma el `proof` JWT (`typ: openid4vci-proof+jwt`) con el `c_nonce` del emisor.
- **Emisión inmediata y diferida:** canjea el `pre-authorized_code`, solicita `POST /{slug}/credential`, soporta polling de `POST /{slug}/deferred_credential`, verifica la firma ES256 del `vc+jwt` contra `/.well-known/jwks.json` y el binding `cnf.jkt`.
- **Almacenamiento cifrado (`AES-256-GCM`):** cifra credenciales y transacciones diferidas pendientes con clave AES-256 en Android Keystore (`dev.example.hukid_wallet/vault`) antes de persistir en disco.
- **Escáner QR:** «Recibir credencial» y «Presentar credencial» leen el QR con el escáner de códigos de Google Play services (`play-services-code-scanner`, canal `dev.example.hukid_wallet/scanner`), sin permiso `CAMERA`. Cada pantalla acepta sólo su esquema. Requiere un dispositivo con Google Play services, que puede necesitar red para descargar el módulo la primera vez. En la app no hay campo para pegar enlaces; el campo sólo existe sin escáner (laboratorio y pruebas). Escanear no prueba la identidad del validador ni del emisor.
- **Tarjeta de credencial:** «Mi wallet» y la selección de «Presentar credencial» comparten una tarjeta (emisor, título, titular, código y fecha de recepción); al tocarla en «Mi wallet» se abre el detalle. Es sólo presentación local: no muestra estado de validez ni cambia lo que se envía al validador.
- **Confianza en el validador:** toda solicitud OID4VP debe venir firmada con una clave de validador conocida; sin claves configuradas la wallet la rechaza. La única fuente implementada es la de laboratorio ([ADR-0037](../../docs/decisions/ADR-0037.md)): con `HUKID_ALLOW_INSECURE_LOOPBACK=true`, pasar `HUKID_LAB_VERIFIER_JWK` (clave pública, base64) y `HUKID_LAB_VERIFIER_CA` (CA PEM, base64). La confianza de producción está pendiente.
- **Pase de ingreso ([ADR-0038](../../docs/decisions/ADR-0038.md)):** en el detalle de una credencial con `recipient.registrationId` y `event.id`, «Mostrar para ingresar» firma una presentación con la clave del titular, obtiene de HukID un código de un solo uso (60 s) y lo muestra como QR (`hukid-pass://v1?code=…`). La dirección sale del emisor guardado. Requiere conexión. Es un protocolo propio, no OID4VP.
- **Deep link Android:** recibe enlaces `openid-credential-offer://` mediante `intent-filter` en `MainActivity.kt`.

## Checks en Docker

Construye la imagen ligera con Flutter 3.50.0 (o la imagen completa `development` de [deploy/wallet/Dockerfile](../../deploy/wallet/Dockerfile)) y ejecuta análisis y pruebas montando `src/wallet`:

```sh
docker build --target sdk -f deploy/wallet/Dockerfile -t hukid-wallet-sdk:local .
docker run --rm -e PUB_CACHE=/workspace/.pub-cache -v "$PWD/src/wallet:/workspace" hukid-wallet-sdk:local flutter pub get
docker run --rm --network none -e PUB_CACHE=/workspace/.pub-cache -v "$PWD/src/wallet:/workspace" hukid-wallet-sdk:local flutter analyze --no-pub
docker run --rm --network none -e PUB_CACHE=/workspace/.pub-cache -v "$PWD/src/wallet:/workspace" hukid-wallet-sdk:local flutter test --no-pub
```

Para validar contra un emisor HTTP en loopback local durante pruebas de desarrollo, compila pasando `--dart-define=HUKID_ALLOW_INSECURE_LOOPBACK=true`.
