import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'crypto_p256.dart';
import 'issuance.dart';
import 'keystore.dart';

const String preAuthorizedGrantType =
    'urn:ietf:params:oauth:grant-type:pre-authorized_code';

class Oid4vciHttpResponse {
  const Oid4vciHttpResponse({required this.statusCode, required this.body});
  final int statusCode;
  final String body;
}

/// Abstract HTTP transport for OID4VCI calls (implemented with `dart:io` in runtime).
abstract interface class Oid4vciHttpClient {
  Future<Oid4vciHttpResponse> get(Uri uri, {Map<String, String>? headers});
  Future<Oid4vciHttpResponse> post(
    Uri uri, {
    required Map<String, String> headers,
    required String body,
  });
}

class IoOid4vciHttpClient implements Oid4vciHttpClient {
  IoOid4vciHttpClient({
    HttpClient? client,
    this.timeout = const Duration(seconds: 15),
    this.maxResponseBytes = 256 * 1024,
  }) : _client = client ?? HttpClient() {
    _client.connectionTimeout = timeout;
  }

  final HttpClient _client;
  final Duration timeout;
  final int maxResponseBytes;

  @override
  Future<Oid4vciHttpResponse> get(Uri uri, {Map<String, String>? headers}) =>
      _send('GET', uri, headers: headers);

  @override
  Future<Oid4vciHttpResponse> post(
    Uri uri, {
    required Map<String, String> headers,
    required String body,
  }) => _send('POST', uri, headers: headers, body: body);

  Future<Oid4vciHttpResponse> _send(
    String method,
    Uri uri, {
    Map<String, String>? headers,
    String? body,
  }) async {
    final req = await _client.openUrl(method, uri).timeout(timeout);
    req.followRedirects = false;
    req.headers.set(HttpHeaders.acceptHeader, 'application/json');
    if (headers != null) {
      headers.forEach((k, v) => req.headers.set(k, v));
    }
    if (body != null) {
      final encoded = utf8.encode(body);
      req.contentLength = encoded.length;
      req.add(encoded);
    }
    final res = await req.close().timeout(timeout);
    final chunks = <int>[];
    await for (final chunk in res.timeout(timeout)) {
      if (chunks.length + chunk.length > maxResponseBytes) {
        throw const HttpException('response exceeds size limit');
      }
      chunks.addAll(chunk);
    }
    return Oid4vciHttpResponse(
      statusCode: res.statusCode,
      body: utf8.decode(chunks),
    );
  }
}

/// Security and interoperability options for [Oid4vciOfferAdapter].
class Oid4vciConfig {
  const Oid4vciConfig({
    this.allowedIssuerOrigins,
    this.allowInsecureLoopback = false,
    this.verifyIssuerSignature = true,
    this.now,
  });

  /// When non-null, restricts offers and issuers to these exact origins
  /// (e.g. `https://issuer.hukid.pe`).
  final Set<String>? allowedIssuerOrigins;

  /// Allows plain HTTP strictly for loopback hosts (`localhost`, `127.0.0.1`,
  /// `::1`, `10.0.2.2`) during local development/testing.
  final bool allowInsecureLoopback;

  /// Verifies issuer ES256 signature against `<issuer>/.well-known/jwks.json`.
  final bool verifyIssuerSignature;

  final DateTime Function()? now;
}

class _ResolvedOfferSession {
  const _ResolvedOfferSession({
    required this.credentialIssuer,
    required this.issuerDisplayName,
    required this.credentialTitle,
    required this.configurationId,
    required this.preAuthorizedCode,
    required this.authorizationServer,
    required this.credentialEndpoint,
    required this.nonceEndpoint,
    required this.deferredEndpoint,
  });

  final String credentialIssuer;
  final String issuerDisplayName;
  final String credentialTitle;
  final String configurationId;
  final String preAuthorizedCode;
  final String authorizationServer;
  final String credentialEndpoint;
  final String nonceEndpoint;
  final String? deferredEndpoint;
}

/// Production/lab OID4VCI 1.0 client implementing [OfferAdapter].
class Oid4vciOfferAdapter implements OfferAdapter {
  Oid4vciOfferAdapter({
    required HolderKeyStore keyStore,
    required CredentialVault vault,
    Oid4vciHttpClient? httpClient,
    Oid4vciConfig config = const Oid4vciConfig(),
  }) : _keyStore = keyStore,
       _vault = vault,
       _http = httpClient ?? IoOid4vciHttpClient(),
       _config = config;

  final HolderKeyStore _keyStore;
  final CredentialVault _vault;
  final Oid4vciHttpClient _http;
  final Oid4vciConfig _config;
  final Map<String, _ResolvedOfferSession> _sessions =
      <String, _ResolvedOfferSession>{};
  final Random _random = Random.secure();

  DateTime _now() => (_config.now?.call() ?? DateTime.now()).toUtc();

  @override
  Future<OfferPreview?> preview(String link) async {
    final offerUri = _parseOfferUri(link);
    if (offerUri == null) return null;

    final offerRes = await _http.get(offerUri);
    if (offerRes.statusCode != 200) return null;
    final offerJson = _decodeJsonMap(offerRes.body);
    if (offerJson == null) return null;

    final rawIssuer = offerJson['credential_issuer'];
    final configIds = offerJson['credential_configuration_ids'];
    final grants = offerJson['grants'];
    if (rawIssuer is! String ||
        configIds is! List<dynamic> ||
        configIds.isEmpty ||
        grants is! Map<String, dynamic>) {
      return null;
    }
    final configId = configIds.first;
    if (configId is! String || configId.trim().isEmpty) return null;

    final preAuth = grants[preAuthorizedGrantType];
    if (preAuth is! Map<String, dynamic>) return null;
    final preAuthCode = preAuth['pre-authorized_code'];
    if (preAuthCode is! String || preAuthCode.trim().isEmpty) return null;

    final issuerUri = _validateUri(rawIssuer, checkAllowedOrigin: true);
    final issuerPrefix = _trimRightSlash(issuerUri?.path ?? '');
    if (issuerUri == null ||
        _originOf(issuerUri) != _originOf(offerUri) ||
        (issuerPrefix.isNotEmpty &&
            offerUri.path != issuerPrefix &&
            !offerUri.path.startsWith('$issuerPrefix/'))) {
      return null;
    }

    final metaUri = _appendPath(
      issuerUri,
      '/.well-known/openid-credential-issuer',
    );
    final metaRes = await _http.get(metaUri);
    if (metaRes.statusCode != 200) return null;
    final metaJson = _decodeJsonMap(metaRes.body);
    if (metaJson == null) return null;

    if (metaJson['credential_issuer'] != rawIssuer) return null;
    final authServers = metaJson['authorization_servers'];
    final credEndpoint = metaJson['credential_endpoint'];
    final nonceEndpoint = metaJson['nonce_endpoint'];
    final deferredEndpoint = metaJson['deferred_credential_endpoint'];
    final configs = metaJson['credential_configurations_supported'];
    if (authServers is! List<dynamic> ||
        authServers.isEmpty ||
        authServers.first is! String ||
        credEndpoint is! String ||
        nonceEndpoint is! String ||
        configs is! Map<String, dynamic>) {
      return null;
    }

    final authServer = authServers.first as String;
    if (_validateUri(authServer, checkAllowedOrigin: false) == null) {
      return null;
    }
    final credEpUri = _validateSameOrigin(issuerUri, credEndpoint);
    final nonceEpUri = _validateSameOrigin(issuerUri, nonceEndpoint);
    if (credEpUri == null || nonceEpUri == null) return null;

    String? validatedDeferred;
    if (deferredEndpoint != null) {
      if (deferredEndpoint is! String ||
          _validateSameOrigin(issuerUri, deferredEndpoint) == null) {
        return null;
      }
      validatedDeferred = deferredEndpoint;
    }

    final cfg = configs[configId];
    if (cfg is! Map<String, dynamic> || !_supportsVCDMProofProfile(cfg)) {
      return null;
    }

    final title = _extractDisplayName(cfg) ?? configId;
    final issuerDisplayName = '${issuerUri.host}${issuerUri.path}';
    final previewId = _newPreviewId();

    _sessions.clear();
    _sessions[previewId] = _ResolvedOfferSession(
      credentialIssuer: rawIssuer,
      issuerDisplayName: issuerDisplayName,
      credentialTitle: title,
      configurationId: configId,
      preAuthorizedCode: preAuthCode,
      authorizationServer: authServer,
      credentialEndpoint: credEndpoint,
      nonceEndpoint: nonceEndpoint,
      deferredEndpoint: validatedDeferred,
    );

    return OfferPreview(
      issuer: issuerDisplayName,
      title: title,
      configurationId: configId,
      credentialIssuer: rawIssuer,
      previewId: previewId,
    );
  }

  @override
  Future<ReceiveOutcome> request(OfferPreview offer) async {
    final session = _sessions.remove(offer.previewId);
    if (session == null) {
      return const ReceiveOutcome.unavailable();
    }

    final authUri = _validateUri(
      session.authorizationServer,
      checkAllowedOrigin: false,
    );
    if (authUri == null) {
      return const ReceiveOutcome.unavailable();
    }

    // 1. Discover AS token endpoint (RFC 8414).
    final asMetaUri = _asDiscoveryUri(authUri);
    final asRes = await _http.get(asMetaUri);
    if (asRes.statusCode != 200) {
      return const ReceiveOutcome.unavailable();
    }
    final asJson = _decodeJsonMap(asRes.body);
    if (asJson == null || asJson['issuer'] != session.authorizationServer) {
      return const ReceiveOutcome.unavailable();
    }
    final rawTokenEp = asJson['token_endpoint'];
    final grants = asJson['grant_types_supported'];
    if (rawTokenEp is! String ||
        grants is! List<dynamic> ||
        !grants.contains(preAuthorizedGrantType)) {
      return const ReceiveOutcome.unavailable();
    }
    final tokenUri = _validateSameOrigin(authUri, rawTokenEp);
    if (tokenUri == null) {
      return const ReceiveOutcome.unavailable();
    }

    // 2. Redeem pre-authorized_code for OID4VCI access token + credential identifier.
    final formBody = Uri(
      queryParameters: <String, String>{
        'grant_type': preAuthorizedGrantType,
        'pre-authorized_code': session.preAuthorizedCode,
      },
    ).query;
    final tokRes = await _http.post(
      tokenUri,
      headers: const <String, String>{
        HttpHeaders.contentTypeHeader: 'application/x-www-form-urlencoded',
      },
      body: formBody,
    );
    if (tokRes.statusCode != 200) {
      return const ReceiveOutcome.unavailable();
    }
    final tokJson = _decodeJsonMap(tokRes.body);
    if (tokJson == null) return const ReceiveOutcome.unavailable();
    final accessToken = tokJson['access_token'];
    final credIdentifier = _extractCredentialIdentifier(
      tokJson['authorization_details'],
      session.configurationId,
    );
    if (accessToken is! String ||
        accessToken.isEmpty ||
        credIdentifier == null) {
      return const ReceiveOutcome.unavailable();
    }

    // 3. Obtain fresh c_nonce challenge.
    final nonceUri = Uri.parse(session.nonceEndpoint);
    final nonceRes = await _http.post(
      nonceUri,
      headers: const <String, String>{
        HttpHeaders.contentTypeHeader: 'application/json',
      },
      body: '{}',
    );
    if (nonceRes.statusCode != 200) {
      return const ReceiveOutcome.unavailable();
    }
    final nonceJson = _decodeJsonMap(nonceRes.body);
    final cNonce = nonceJson?['c_nonce'];
    if (cNonce is! String || cNonce.isEmpty) {
      return const ReceiveOutcome.unavailable();
    }

    // 4. Ensure non-exportable P-256 holder key and sign openid4vci-proof+jwt.
    final keyAlias = safeVaultId('hukid_key', session.credentialIssuer);
    final holderJwk = await _keyStore.ensureKey(keyAlias);
    final holderJkt = holderJwk.thumbprint();
    final proofJwt = await buildHolderProofJwt(
      publicJwk: holderJwk,
      signEs256: (bytes) => _keyStore.signEs256(keyAlias, bytes),
      audience: session.credentialIssuer,
      nonce: cNonce,
      issuedAt: _now(),
    );

    // 5. Request credential issuance (immediate 200 or deferred 202).
    final credRes = await _http.post(
      Uri.parse(session.credentialEndpoint),
      headers: <String, String>{
        HttpHeaders.authorizationHeader: 'Bearer $accessToken',
        HttpHeaders.contentTypeHeader: 'application/json',
      },
      body: jsonEncode(<String, dynamic>{
        'credential_identifier': credIdentifier,
        'proofs': <String, dynamic>{
          'jwt': <String>[proofJwt],
        },
      }),
    );

    if (credRes.statusCode == 200) {
      final vcJwt = _extractFirstCredential(credRes.body);
      if (vcJwt == null) return const ReceiveOutcome.unavailable();
      final stored = await _verifyAndWrapVc(
        vcJwt: vcJwt,
        credentialIssuer: session.credentialIssuer,
        issuerDisplayName: session.issuerDisplayName,
        configurationId: session.configurationId,
        title: session.credentialTitle,
        expectedHolderJkt: holderJkt,
        keyAlias: keyAlias,
      );
      if (stored == null) return const ReceiveOutcome.unavailable();
      await _vault.saveCredential(stored);
      return ReceiveOutcome.stored(stored);
    }

    if (credRes.statusCode == 202 && session.deferredEndpoint != null) {
      final defJson = _decodeJsonMap(credRes.body);
      final txId = defJson?['transaction_id'];
      final rawInterval = defJson?['interval'];
      if (txId is! String || txId.isEmpty) {
        return const ReceiveOutcome.unavailable();
      }
      final interval = rawInterval is int && rawInterval > 0 ? rawInterval : 5;
      final pending = PendingDeferredIssuance(
        id: safeVaultId('pending', '${session.credentialIssuer}|$txId'),
        credentialIssuer: session.credentialIssuer,
        deferredEndpoint: session.deferredEndpoint!,
        accessToken: accessToken,
        transactionId: txId,
        intervalSeconds: interval,
        configurationId: session.configurationId,
        title: session.credentialTitle,
        issuerDisplayName: session.issuerDisplayName,
        holderJkt: holderJkt,
        keyAlias: keyAlias,
        createdAtIso: _now().toIso8601String(),
      );
      await _vault.savePendingDeferred(pending);
      return ReceiveOutcome.pending(pending);
    }

    return const ReceiveOutcome.unavailable();
  }

  @override
  Future<ReceiveOutcome> pollDeferred(PendingDeferredIssuance pending) async {
    final issuerUri = _validateUri(
      pending.credentialIssuer,
      checkAllowedOrigin: true,
    );
    if (issuerUri == null) {
      await _vault.deletePendingDeferred(pending.id);
      return const ReceiveOutcome.unavailable();
    }
    final deferredUri = _validateSameOrigin(issuerUri, pending.deferredEndpoint);
    if (deferredUri == null) {
      await _vault.deletePendingDeferred(pending.id);
      return const ReceiveOutcome.unavailable();
    }

    final res = await _http.post(
      deferredUri,
      headers: <String, String>{
        HttpHeaders.authorizationHeader: 'Bearer ${pending.accessToken}',
        HttpHeaders.contentTypeHeader: 'application/json',
      },
      body: jsonEncode(<String, dynamic>{
        'transaction_id': pending.transactionId,
      }),
    );

    if (res.statusCode == 200) {
      final vcJwt = _extractFirstCredential(res.body);
      if (vcJwt == null) {
        await _vault.deletePendingDeferred(pending.id);
        return const ReceiveOutcome.unavailable();
      }
      final stored = await _verifyAndWrapVc(
        vcJwt: vcJwt,
        credentialIssuer: pending.credentialIssuer,
        issuerDisplayName: pending.issuerDisplayName,
        configurationId: pending.configurationId,
        title: pending.title,
        expectedHolderJkt: pending.holderJkt,
        keyAlias: pending.keyAlias,
      );
      if (stored == null) {
        await _vault.deletePendingDeferred(pending.id);
        return const ReceiveOutcome.unavailable();
      }
      await _vault.saveCredential(stored);
      await _vault.deletePendingDeferred(pending.id);
      return ReceiveOutcome.stored(stored);
    }

    if (res.statusCode == 400) {
      final errJson = _decodeJsonMap(res.body);
      if (errJson?['error'] == 'issuance_pending') {
        return ReceiveOutcome.pending(pending);
      }
      await _vault.deletePendingDeferred(pending.id);
      return const ReceiveOutcome.unavailable();
    }

    if (res.statusCode == 401 || res.statusCode == 404) {
      await _vault.deletePendingDeferred(pending.id);
      return const ReceiveOutcome.unavailable();
    }

    return const ReceiveOutcome.unavailable();
  }

  Future<StoredCredential?> _verifyAndWrapVc({
    required String vcJwt,
    required String credentialIssuer,
    required String issuerDisplayName,
    required String configurationId,
    required String title,
    required String expectedHolderJkt,
    required String keyAlias,
  }) async {
    final parts = vcJwt.split('.');
    if (parts.length != 3 ||
        parts[0].isEmpty ||
        parts[1].isEmpty ||
        parts[2].isEmpty) {
      return null;
    }

    Map<String, dynamic>? header;
    Map<String, dynamic>? payload;
    try {
      header = _decodeJsonMap(utf8.decode(base64UrlNoPadDecode(parts[0])));
      payload = _decodeJsonMap(utf8.decode(base64UrlNoPadDecode(parts[1])));
    } catch (_) {
      return null;
    }
    if (header == null || payload == null) return null;
    if (header['alg'] != 'ES256' || header['typ'] != 'vc+jwt') {
      return null;
    }
    final kid = header['kid'];
    if (kid is! String || kid.isEmpty) return null;

    final vcIssuer = payload['issuer'] ?? payload['iss'];
    if (vcIssuer != credentialIssuer) return null;

    final cnf = payload['cnf'];
    if (cnf is! Map<String, dynamic> || cnf['jkt'] != expectedHolderJkt) {
      return null;
    }

    final rawValidUntil = payload['validUntil'];
    if (rawValidUntil is String && rawValidUntil.isNotEmpty) {
      final exp = DateTime.tryParse(rawValidUntil);
      if (exp == null || !exp.isAfter(_now())) {
        return null;
      }
    }

    if (_config.verifyIssuerSignature) {
      final issuerUri = Uri.parse(credentialIssuer);
      final jwksUri = _appendPath(issuerUri, '/.well-known/jwks.json');
      final jwksRes = await _http.get(jwksUri);
      if (jwksRes.statusCode != 200) return null;
      final jwksJson = _decodeJsonMap(jwksRes.body);
      final keys = jwksJson?['keys'];
      if (keys is! List<dynamic>) return null;

      PublicEcJwk? matchedKey;
      for (final rawKey in keys) {
        if (rawKey is! Map<String, dynamic>) continue;
        if (rawKey['kid'] != kid) continue;
        try {
          matchedKey = PublicEcJwk.fromJson(rawKey);
          break;
        } catch (_) {
          continue;
        }
      }
      if (matchedKey == null) return null;

      late final sigBytes = base64UrlNoPadDecode(parts[2]);
      if (sigBytes.length != 64) return null;
      final signingInput = utf8.encode('${parts[0]}.${parts[1]}');
      final ok = P256Curve.verifyEs256(matchedKey, signingInput, sigBytes);
      if (!ok) return null;
    }

    final credRawId = payload['id'];
    final uniqueKey = credRawId is String && credRawId.isNotEmpty
        ? credRawId
        : vcJwt;
    return StoredCredential(
      id: safeVaultId('cred', '$credentialIssuer|$uniqueKey'),
      credentialIssuer: credentialIssuer,
      configurationId: configurationId,
      title: title,
      issuerDisplayName: issuerDisplayName,
      holderJkt: expectedHolderJkt,
      keyAlias: keyAlias,
      vcJwt: vcJwt,
      receivedAtIso: _now().toIso8601String(),
    );
  }

  Uri? _parseOfferUri(String link) {
    final trimmed = link.trim();
    if (!trimmed.startsWith('openid-credential-offer://')) return null;
    final parsed = Uri.tryParse(trimmed);
    if (parsed == null) return null;
    final offerRaw = parsed.queryParameters['credential_offer_uri'];
    if (offerRaw == null ||
        offerRaw.isEmpty ||
        parsed.queryParameters.length != 1) {
      return null;
    }
    return _validateUri(offerRaw, checkAllowedOrigin: true);
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
    if (parsed.scheme == 'https') {
      if (checkAllowedOrigin &&
          _config.allowedIssuerOrigins != null &&
          !_config.allowedIssuerOrigins!.contains(_originOf(parsed))) {
        return null;
      }
      return parsed;
    }
    if (parsed.scheme == 'http' &&
        _config.allowInsecureLoopback &&
        _isLoopbackHost(parsed.host)) {
      if (checkAllowedOrigin &&
          _config.allowedIssuerOrigins != null &&
          !_config.allowedIssuerOrigins!.contains(_originOf(parsed))) {
        return null;
      }
      return parsed;
    }
    return null;
  }

  Uri? _validateSameOrigin(Uri expectedBase, String rawTarget) {
    final parsed = _validateUri(rawTarget, checkAllowedOrigin: false);
    if (parsed == null) return null;
    return _originOf(parsed) == _originOf(expectedBase) ? parsed : null;
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

  Uri _appendPath(Uri base, String suffix) {
    final cleanBasePath = _trimRightSlash(base.path);
    return base.replace(path: '$cleanBasePath$suffix', query: null);
  }

  Uri _asDiscoveryUri(Uri authUri) {
    final basePath = _trimRightSlash(authUri.path);
    final suffix = basePath == '/' || basePath.isEmpty ? '' : basePath;
    return authUri.replace(
      path: '/.well-known/oauth-authorization-server$suffix',
      query: null,
    );
  }

  String _trimRightSlash(String s) =>
      s.endsWith('/') ? s.substring(0, s.length - 1) : s;

  Map<String, dynamic>? _decodeJsonMap(String body) {
    try {
      final decoded = jsonDecode(body);
      return decoded is Map<String, dynamic> ? decoded : null;
    } catch (_) {
      return null;
    }
  }

  bool _supportsVCDMProofProfile(Map<String, dynamic> cfg) {
    final format = cfg['format'];
    if (format != 'vc+jwt' && format != 'application/vc+jwt') return false;
    final algs = cfg['credential_signing_alg_values_supported'];
    if (algs is! List<dynamic> || !algs.contains('ES256')) return false;
    final proofTypes = cfg['proof_types_supported'];
    if (proofTypes is! Map<String, dynamic>) return false;
    final jwtProof = proofTypes['jwt'];
    if (jwtProof is! Map<String, dynamic>) return false;
    final proofAlgs = jwtProof['proof_signing_alg_values_supported'];
    return proofAlgs is List<dynamic> && proofAlgs.contains('ES256');
  }

  String? _extractDisplayName(Map<String, dynamic> cfg) {
    final meta = cfg['credential_metadata'];
    if (meta is! Map<String, dynamic>) return null;
    final display = meta['display'];
    if (display is! List<dynamic> || display.isEmpty) return null;
    final first = display.first;
    if (first is! Map<String, dynamic>) return null;
    final name = first['name'];
    return name is String && name.trim().isNotEmpty ? name.trim() : null;
  }

  String? _extractCredentialIdentifier(
    dynamic rawDetails,
    String expectedConfigId,
  ) {
    if (rawDetails is! List<dynamic>) return null;
    for (final entry in rawDetails) {
      if (entry is! Map<String, dynamic>) continue;
      if (entry['type'] != 'openid_credential') continue;
      if (entry['credential_configuration_id'] != expectedConfigId) continue;
      final ids = entry['credential_identifiers'];
      if (ids is List<dynamic> &&
          ids.isNotEmpty &&
          ids.first is String &&
          (ids.first as String).isNotEmpty) {
        return ids.first as String;
      }
    }
    return null;
  }

  String? _extractFirstCredential(String body) {
    final decoded = _decodeJsonMap(body);
    final list = decoded?['credentials'];
    if (list is! List<dynamic> || list.isEmpty) return null;
    final first = list.first;
    if (first is! Map<String, dynamic>) return null;
    final cred = first['credential'];
    return cred is String && cred.isNotEmpty ? cred : null;
  }

  String _newPreviewId() {
    final bytes = List<int>.generate(16, (_) => _random.nextInt(256));
    return base64UrlNoPadEncode(bytes);
  }
}
