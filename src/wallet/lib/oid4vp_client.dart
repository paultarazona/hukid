import 'dart:convert';
import 'dart:typed_data';

import 'crypto_jwe.dart';
import 'crypto_p256.dart';
import 'keystore.dart';
import 'oid4vci_client.dart';

const String oid4vpScheme = 'openid4vp://';
const String oid4vpSelfIssuedAudience = 'https://self-issued.me/v2';
const String oid4vpRequestObjectType = 'oauth-authz-req+jwt';
const String oid4vpResponseModeDirectPostJwt = 'direct_post.jwt';
const String hukidVcJwtFormat = 'application/vc+jwt';

enum PresentationState { submitted, rejected, unavailable }

class PresentationOutcome {
  const PresentationOutcome({required this.state, this.detail});

  final PresentationState state;
  final String? detail;
}

class ParsedOid4vpLaunchUri {
  const ParsedOid4vpLaunchUri({
    required this.clientId,
    required this.requestUri,
  });

  final String clientId;
  final Uri requestUri;
}

class PresentationRequestSummary {
  const PresentationRequestSummary({
    required this.clientId,
    required this.requestUri,
    required this.responseUri,
    required this.state,
    required this.nonce,
    required this.credentialQueryId,
    required this.encryptionKey,
    required this.expiresAt,
    required this.signatureVerified,
  });

  final String clientId;
  final Uri requestUri;
  final Uri responseUri;
  final String state;
  final String nonce;
  final String credentialQueryId;
  final PublicEcJwk encryptionKey;
  final DateTime expiresAt;
  final bool signatureVerified;
}

abstract interface class PresentationAdapter {
  Future<PresentationRequestSummary> fetchRequest(String launchUri);

  Future<PresentationOutcome> presentCredential({
    required PresentationRequestSummary request,
    required StoredCredential credential,
  });
}

class UnavailableVerifier implements PresentationAdapter {
  const UnavailableVerifier();

  @override
  Future<PresentationRequestSummary> fetchRequest(String launchUri) =>
      Future<PresentationRequestSummary>.error(
        StateError('Sin validador configurado. Integración no disponible.'),
      );

  @override
  Future<PresentationOutcome> presentCredential({
    required PresentationRequestSummary request,
    required StoredCredential credential,
  }) async => const PresentationOutcome(
    state: PresentationState.unavailable,
    detail: 'Sin validador configurado. Integración no disponible.',
  );
}

/// OID4VP presentation client aligned with HukID `internal/oid4vp` (`FEAT-004`).
class Oid4vpPresentationAdapter implements PresentationAdapter {
  Oid4vpPresentationAdapter({
    required HolderKeyStore keyStore,
    Oid4vciHttpClient? httpClient,
    Oid4vciConfig config = const Oid4vciConfig(),
    Map<String, PublicEcJwk>? verifierSigningKeys,
    Set<String>? allowedVerifierOrigins,
  }) : _keyStore = keyStore,
       _http = httpClient ?? IoOid4vciHttpClient(),
       _config = config,
       _verifierSigningKeys = verifierSigningKeys ?? const <String, PublicEcJwk>{},
       _allowedVerifierOrigins = allowedVerifierOrigins;

  final HolderKeyStore _keyStore;
  final Oid4vciHttpClient _http;
  final Oid4vciConfig _config;
  final Map<String, PublicEcJwk> _verifierSigningKeys;
  final Set<String>? _allowedVerifierOrigins;

  DateTime _now() => (_config.now?.call() ?? DateTime.now()).toUtc();

  ParsedOid4vpLaunchUri parseLaunchUri(String raw) {
    final trimmed = raw.trim();
    if (!trimmed.startsWith(oid4vpScheme)) {
      throw const FormatException('el enlace debe iniciar con openid4vp://');
    }
    final parsed = Uri.tryParse(trimmed);
    if (parsed == null) {
      throw const FormatException('URI openid4vp inválida');
    }
    final clientId = parsed.queryParameters['client_id']?.trim() ?? '';
    final requestUriRaw = parsed.queryParameters['request_uri']?.trim() ?? '';
    final method = parsed.queryParameters['request_uri_method']?.trim();
    if (clientId.isEmpty || requestUriRaw.isEmpty) {
      throw const FormatException('faltan client_id o request_uri en el enlace');
    }
    if (method != null && method.isNotEmpty && method.toLowerCase() != 'get') {
      throw FormatException('request_uri_method no soportado: $method');
    }
    final requestUri = _validateUri(requestUriRaw, checkAllowedOrigin: true);
    if (requestUri == null) {
      throw const FormatException('request_uri inválida o sin HTTPS');
    }
    return ParsedOid4vpLaunchUri(clientId: clientId, requestUri: requestUri);
  }

  @override
  Future<PresentationRequestSummary> fetchRequest(String launchUri) async {
    final launch = parseLaunchUri(launchUri);
    final res = await _http.get(
      launch.requestUri,
      headers: const <String, String>{
        'accept': 'application/oauth-authz-req+jwt',
      },
    );
    if (res.statusCode != 200 || res.body.trim().isEmpty) {
      throw StateError('No se pudo obtener el request object (${res.statusCode}).');
    }
    final parts = res.body.trim().split('.');
    if (parts.length != 3 ||
        parts[0].isEmpty ||
        parts[1].isEmpty ||
        parts[2].isEmpty) {
      throw const FormatException('request object no es un JWT compacto válido');
    }
    final header = _decodeJsonMap(utf8.decode(base64UrlNoPadDecode(parts[0])));
    final payload = _decodeJsonMap(utf8.decode(base64UrlNoPadDecode(parts[1])));
    if (header == null || payload == null) {
      throw const FormatException('request object malformado');
    }
    if (header['alg'] != 'ES256' || header['typ'] != oid4vpRequestObjectType) {
      throw const FormatException('encabezado JWT del validador inválido');
    }

    final kid = header['kid'] is String ? header['kid'] as String : '';
    var signatureVerified = false;
    if (_verifierSigningKeys.isNotEmpty) {
      final verificationKey = _verifierSigningKeys[kid];
      if (verificationKey == null) {
        throw FormatException('kid del validador desconocido: $kid');
      }
      final sigBytes = base64UrlNoPadDecode(parts[2]);
      final signingInput = utf8.encode('${parts[0]}.${parts[1]}');
      if (!P256Curve.verifyEs256(verificationKey, signingInput, sigBytes)) {
        throw const FormatException('firma del request object inválida');
      }
      signatureVerified = true;
    }

    if (payload['client_id'] != launch.clientId ||
        payload['iss'] != launch.clientId) {
      throw const FormatException('client_id o iss no coinciden con la solicitud');
    }
    if (payload['aud'] != oid4vpSelfIssuedAudience) {
      throw const FormatException('aud del request object inválido');
    }
    if (payload['response_type'] != 'vp_token' ||
        payload['response_mode'] != oid4vpResponseModeDirectPostJwt) {
      throw const FormatException('response_type o response_mode no soportados');
    }

    final responseUriRaw = payload['response_uri'];
    if (responseUriRaw is! String || responseUriRaw.isEmpty) {
      throw const FormatException('response_uri faltante');
    }
    final responseUri = _validateUri(
      responseUriRaw,
      checkAllowedOrigin: false,
    );
    if (responseUri == null ||
        _originOf(responseUri) != _originOf(launch.requestUri)) {
      throw const FormatException('response_uri inválida o de distinto origen');
    }

    final nonce = payload['nonce'];
    final state = payload['state'];
    if (nonce is! String ||
        nonce.isEmpty ||
        state is! String ||
        state.isEmpty) {
      throw const FormatException('nonce o state faltantes');
    }

    final rawExp = payload['exp'];
    if (rawExp is! num) {
      throw const FormatException('exp faltante en el request object');
    }
    final expiresAt = DateTime.fromMillisecondsSinceEpoch(
      rawExp.toInt() * 1000,
      isUtc: true,
    );
    if (!expiresAt.isAfter(_now())) {
      throw const FormatException('la solicitud de verificación expiró');
    }

    final credentialQueryId = _extractVcQueryId(payload['dcql_query']);
    final encryptionKey = _extractEncryptionKey(payload['client_metadata']);

    return PresentationRequestSummary(
      clientId: launch.clientId,
      requestUri: launch.requestUri,
      responseUri: responseUri,
      state: state,
      nonce: nonce,
      credentialQueryId: credentialQueryId,
      encryptionKey: encryptionKey,
      expiresAt: expiresAt,
      signatureVerified: signatureVerified,
    );
  }

  @override
  Future<PresentationOutcome> presentCredential({
    required PresentationRequestSummary request,
    required StoredCredential credential,
  }) async {
    if (!request.expiresAt.isAfter(_now())) {
      return const PresentationOutcome(
        state: PresentationState.rejected,
        detail: 'La solicitud de verificación expiró antes de enviarse.',
      );
    }

    final holderJwk = await _keyStore.ensureKey(credential.keyAlias);
    if (holderJwk.thumbprint() != credential.holderJkt) {
      return const PresentationOutcome(
        state: PresentationState.rejected,
        detail: 'La llave del dispositivo no coincide con cnf.jkt de la credencial.',
      );
    }

    final vpJwt = await buildVerifiablePresentationJwt(
      holderPublicJwk: holderJwk,
      signEs256: (signingInput) =>
          _keyStore.signEs256(credential.keyAlias, signingInput),
      audience: request.clientId,
      nonce: request.nonce,
      credentials: <String>[credential.vcJwt],
    );

    final responseJson = jsonEncode(<String, dynamic>{
      'vp_token': <String, dynamic>{
        request.credentialQueryId: <String>[vpJwt],
      },
      'state': request.state,
    });

    final jwe = encryptJweEcdhEsA256Gcm(
      recipientKey: request.encryptionKey,
      plaintext: Uint8List.fromList(utf8.encode(responseJson)),
    );

    final res = await _http.post(
      request.responseUri,
      headers: const <String, String>{
        'content-type': 'application/x-www-form-urlencoded',
        'accept': 'application/json',
      },
      body: 'response=${Uri.encodeQueryComponent(jwe)}',
    );
    if (res.statusCode == 200) {
      return const PresentationOutcome(
        state: PresentationState.submitted,
        detail: 'Presentación enviada y aceptada para evaluación.',
      );
    }
    return PresentationOutcome(
      state: PresentationState.rejected,
      detail: 'El validador rechazó la presentación (${res.statusCode}).',
    );
  }

  String _extractVcQueryId(dynamic rawDcql) {
    if (rawDcql is! Map<String, dynamic>) {
      throw const FormatException('dcql_query faltante');
    }
    final credentials = rawDcql['credentials'];
    if (credentials is! List<dynamic> || credentials.isEmpty) {
      throw const FormatException('dcql_query sin credenciales solicitadas');
    }
    for (final entry in credentials) {
      if (entry is! Map<String, dynamic>) continue;
      final id = entry['id'];
      final format = entry['format'];
      if (id is String && id.isNotEmpty && format == hukidVcJwtFormat) {
        return id;
      }
    }
    throw const FormatException(
      'ninguna consulta DCQL solicita formato application/vc+jwt',
    );
  }

  PublicEcJwk _extractEncryptionKey(dynamic rawMetadata) {
    if (rawMetadata is! Map<String, dynamic>) {
      throw const FormatException('client_metadata faltante');
    }
    final supportedEnc = rawMetadata['encrypted_response_enc_values_supported'];
    if (supportedEnc is List<dynamic> && !supportedEnc.contains('A256GCM')) {
      throw const FormatException('cifrado A256GCM no soportado por el validador');
    }
    final jwks = rawMetadata['jwks'];
    if (jwks is! Map<String, dynamic>) {
      throw const FormatException('client_metadata sin jwks');
    }
    final keys = jwks['keys'];
    if (keys is! List<dynamic> || keys.isEmpty) {
      throw const FormatException('client_metadata sin llaves de cifrado');
    }
    for (final rawKey in keys) {
      if (rawKey is! Map<String, dynamic>) continue;
      final use = rawKey['use'];
      final alg = rawKey['alg'];
      final kid = rawKey['kid'];
      if ((use == null || use == 'enc') &&
          (alg == null || alg == 'ECDH-ES') &&
          kid is String &&
          kid.isNotEmpty) {
        try {
          return PublicEcJwk.fromJson(rawKey);
        } catch (_) {
          continue;
        }
      }
    }
    throw const FormatException(
      'no se encontró llave EC P-256 ECDH-ES válida en client_metadata',
    );
  }

  Uri? _validateUri(String raw, {required bool checkAllowedOrigin}) {
    final parsed = Uri.tryParse(raw.trim());
    if (parsed == null ||
        !parsed.hasAuthority ||
        parsed.host.isEmpty ||
        parsed.userInfo.isNotEmpty ||
        parsed.hasFragment) {
      return null;
    }
    final allowedScheme =
        parsed.scheme == 'https' ||
        (parsed.scheme == 'http' &&
            _config.allowInsecureLoopback &&
            _isLoopbackHost(parsed.host));
    if (!allowedScheme) return null;
    if (checkAllowedOrigin &&
        _allowedVerifierOrigins != null &&
        !_allowedVerifierOrigins.contains(_originOf(parsed))) {
      return null;
    }
    return parsed;
  }

  bool _isLoopbackHost(String host) =>
      host == 'localhost' ||
      host == '127.0.0.1' ||
      host == '::1' ||
      host == '10.0.2.2';

  String _originOf(Uri uri) {
    final isDefaultPort =
        (uri.scheme == 'https' && uri.port == 443) ||
        (uri.scheme == 'http' && uri.port == 80) ||
        !uri.hasPort;
    return isDefaultPort
        ? '${uri.scheme}://${uri.host}'
        : '${uri.scheme}://${uri.host}:${uri.port}';
  }

  Map<String, dynamic>? _decodeJsonMap(String body) {
    try {
      final decoded = jsonDecode(body);
      return decoded is Map<String, dynamic> ? decoded : null;
    } catch (_) {
      return null;
    }
  }
}
