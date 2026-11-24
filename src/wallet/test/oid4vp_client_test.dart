import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/crypto_p256.dart';
import 'package:hukid_wallet/keystore.dart';
import 'package:hukid_wallet/oid4vci_client.dart';
import 'package:hukid_wallet/oid4vp_client.dart';

class _MockHukidVerifier {
  _MockHukidVerifier(
    this._server,
    this.signingKey,
    this.encryptionKey,
  ) : origin = 'http://127.0.0.1:${_server.port}',
      clientId = 'x509_san_dns:127.0.0.1:${_server.port}';

  final HttpServer _server;
  final P256KeyPair signingKey;
  final P256KeyPair encryptionKey;
  final String origin;
  final String clientId;

  bool expiredMode = false;
  bool wrongAudience = false;
  bool tamperSignature = false;
  bool wrongOriginResponseUri = false;
  bool rejectPost = false;

  String? lastContentType;
  String? lastResponseJwe;

  static Future<_MockHukidVerifier> start() async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final sigKey = P256KeyPair.generate(kid: 'ver-sig-1');
    final encKey = P256KeyPair.generate(kid: 'ver-enc-1');
    final mock = _MockHukidVerifier(server, sigKey, encKey);
    server.listen(mock._handle);
    return mock;
  }

  Future<void> close() => _server.close(force: true);

  String launchUri([String state = 'state_abc_1']) =>
      'openid4vp://authorize?client_id=${Uri.encodeQueryComponent(clientId)}'
      '&request_uri=${Uri.encodeQueryComponent('$origin/oid4vp/request/$state')}'
      '&request_uri_method=get';

  Future<void> _handle(HttpRequest req) async {
    final body = await utf8.decoder.bind(req).join();
    if (req.method == 'GET' && req.uri.path.startsWith('/oid4vp/request/')) {
      final state = req.uri.path.substring('/oid4vp/request/'.length);
      final nowEpoch = DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000;
      final headerB64 = base64UrlNoPadEncode(
        utf8.encode(
          jsonEncode(<String, dynamic>{
            'alg': 'ES256',
            'typ': 'oauth-authz-req+jwt',
            'kid': signingKey.publicJwk.kid,
          }),
        ),
      );
      final encJwk = <String, dynamic>{
        'kty': 'EC',
        'crv': 'P-256',
        'x': encryptionKey.publicJwk.x,
        'y': encryptionKey.publicJwk.y,
        'kid': encryptionKey.publicJwk.kid,
        'use': 'enc',
        'alg': 'ECDH-ES',
      };
      final payloadB64 = base64UrlNoPadEncode(
        utf8.encode(
          jsonEncode(<String, dynamic>{
            'iss': clientId,
            'aud': wrongAudience ? 'https://other.example' : oid4vpSelfIssuedAudience,
            'client_id': clientId,
            'response_type': 'vp_token',
            'response_mode': 'direct_post.jwt',
            'response_uri': wrongOriginResponseUri
                ? 'https://evil.example/oid4vp/response'
                : '$origin/oid4vp/response',
            'nonce': 'nonce_xyz_123',
            'state': state,
            'iat': nowEpoch - 5,
            'exp': expiredMode ? nowEpoch - 1 : nowEpoch + 300,
            'dcql_query': <String, dynamic>{
              'credentials': <dynamic>[
                <String, dynamic>{
                  'id': 'event_cred',
                  'format': 'application/vc+jwt',
                  'meta': <String, dynamic>{},
                },
              ],
            },
            'client_metadata': <String, dynamic>{
              'jwks': <String, dynamic>{
                'keys': <dynamic>[encJwk],
              },
              'encrypted_response_enc_values_supported': <String>['A256GCM'],
            },
          }),
        ),
      );
      final input = '$headerB64.$payloadB64';
      final sig = signingKey.signEs256(utf8.encode(input));
      if (tamperSignature) {
        sig[2] ^= 0xff;
      }
      final jwt = '$input.${base64UrlNoPadEncode(sig)}';
      req.response.statusCode = 200;
      req.response.headers.set('content-type', 'application/oauth-authz-req+jwt');
      req.response.write(jwt);
      await req.response.close();
      return;
    }

    if (req.method == 'POST' && req.uri.path == '/oid4vp/response') {
      lastContentType = req.headers.value(HttpHeaders.contentTypeHeader);
      final form = Uri.splitQueryString(body);
      lastResponseJwe = form['response'];
      req.response.statusCode = rejectPost ? 400 : 200;
      req.response.headers.set('content-type', 'application/json');
      req.response.write(rejectPost ? '{"error":"invalid_request"}' : '{}');
      await req.response.close();
      return;
    }

    req.response.statusCode = 404;
    await req.response.close();
  }
}

Future<({StoredCredential cred, HolderKeyStore keyStore})> _makeStoredCredential() async {
  final keyStore = MemoryHolderKeyStore();
  const alias = 'holder_key_test';
  final jwk = await keyStore.ensureKey(alias);
  final jkt = jwk.thumbprint();
  final issuerKey = P256KeyPair.generate(kid: 'iss-k1');
  final h = base64UrlNoPadEncode(
    utf8.encode(jsonEncode(<String, String>{'alg': 'ES256', 'typ': 'vc+jwt', 'kid': 'iss-k1'})),
  );
  final p = base64UrlNoPadEncode(
    utf8.encode(
      jsonEncode(<String, dynamic>{
        '@context': <String>['https://www.w3.org/ns/credentials/v2'],
        'type': <String>['VerifiableCredential'],
        'issuer': 'https://issuer.hukid.pe/unas',
        'validFrom': '2026-11-20T00:00:00Z',
        'validUntil': '2027-11-20T00:00:00Z',
        'cnf': <String, String>{'jkt': jkt},
        'credentialSubject': <String, dynamic>{'id': 'did:example:alice'},
      }),
    ),
  );
  final sig = issuerKey.signEs256(utf8.encode('$h.$p'));
  final vcJwt = '$h.$p.${base64UrlNoPadEncode(sig)}';
  return (
    cred: StoredCredential(
      id: 'cred_vp_1',
      credentialIssuer: 'https://issuer.hukid.pe/unas',
      configurationId: 'event_participation_v1',
      title: 'Certificado UNAS',
      issuerDisplayName: 'UNAS Cloud',
      holderJkt: jkt,
      keyAlias: alias,
      vcJwt: vcJwt,
      receivedAtIso: '2026-11-20T00:00:00Z',
    ),
    keyStore: keyStore,
  );
}

void main() {
  test('parseLaunchUri validates scheme, parameters and HTTPS enforcement', () {
    final strictAdapter = Oid4vpPresentationAdapter(
      keyStore: MemoryHolderKeyStore(),
    );
    expect(
      () => strictAdapter.parseLaunchUri('https://example.com'),
      throwsFormatException,
    );
    expect(
      () => strictAdapter.parseLaunchUri(
        'openid4vp://authorize?client_id=c1&request_uri=http%3A%2F%2F127.0.0.1%2Freq',
      ),
      throwsFormatException,
    );
    expect(
      () => strictAdapter.parseLaunchUri(
        'openid4vp://authorize?client_id=c1&request_uri=https%3A%2F%2Fhukid.zentrycore.com%2Freq&request_uri_method=post',
      ),
      throwsFormatException,
    );
    final parsed = strictAdapter.parseLaunchUri(
      'openid4vp://authorize?client_id=x509_san_dns%3Ahukid.zentrycore.com&request_uri=https%3A%2F%2Fhukid.zentrycore.com%2Foid4vp%2Frequest%2Fs1&request_uri_method=get',
    );
    expect(parsed.clientId, 'x509_san_dns:hukid.zentrycore.com');
    expect(parsed.requestUri.toString(), 'https://hukid.zentrycore.com/oid4vp/request/s1');
  });

  test('fetchRequest and presentCredential send valid ECDH-ES JWE response', () async {
    final server = await _MockHukidVerifier.start();
    addTearDown(server.close);
    final setup = await _makeStoredCredential();
    final adapter = Oid4vpPresentationAdapter(
      keyStore: setup.keyStore,
      config: const Oid4vciConfig(allowInsecureLoopback: true),
      verifierSigningKeys: <String, PublicEcJwk>{
        'ver-sig-1': server.signingKey.publicJwk,
      },
    );

    final req = await adapter.fetchRequest(server.launchUri('st_happy'));
    expect(req.signatureVerified, isTrue);
    expect(req.credentialQueryId, 'event_cred');
    expect(req.state, 'st_happy');

    final outcome = await adapter.presentCredential(
      request: req,
      credential: setup.cred,
    );
    expect(outcome.state, PresentationState.submitted);
    expect(server.lastContentType, startsWith('application/x-www-form-urlencoded'));
    expect(server.lastResponseJwe, isNotNull);

    final jweParts = server.lastResponseJwe!.split('.');
    expect(jweParts.length, 5);
    expect(jweParts[1], isEmpty);
    final jweHeader = jsonDecode(
      utf8.decode(base64UrlNoPadDecode(jweParts[0])),
    ) as Map<String, dynamic>;
    expect(jweHeader['alg'], 'ECDH-ES');
    expect(jweHeader['enc'], 'A256GCM');
    expect(jweHeader['kid'], 'ver-enc-1');
    expect(jweHeader['epk'], isA<Map<String, dynamic>>());
  });

  test('fetchRequest rejects tampered signature, expired exp, wrong aud and cross-origin response_uri', () async {
    final server = await _MockHukidVerifier.start();
    addTearDown(server.close);
    final adapter = Oid4vpPresentationAdapter(
      keyStore: MemoryHolderKeyStore(),
      config: const Oid4vciConfig(allowInsecureLoopback: true),
      verifierSigningKeys: <String, PublicEcJwk>{
        'ver-sig-1': server.signingKey.publicJwk,
      },
    );

    server.tamperSignature = true;
    await expectLater(adapter.fetchRequest(server.launchUri()), throwsFormatException);
    server.tamperSignature = false;

    server.expiredMode = true;
    await expectLater(adapter.fetchRequest(server.launchUri()), throwsFormatException);
    server.expiredMode = false;

    server.wrongAudience = true;
    await expectLater(adapter.fetchRequest(server.launchUri()), throwsFormatException);
    server.wrongAudience = false;

    server.wrongOriginResponseUri = true;
    await expectLater(adapter.fetchRequest(server.launchUri()), throwsFormatException);
  });

  test('presentCredential reports rejected on 400 and on mismatched holder key', () async {
    final server = await _MockHukidVerifier.start();
    addTearDown(server.close);
    final setup = await _makeStoredCredential();
    final adapter = Oid4vpPresentationAdapter(
      keyStore: setup.keyStore,
      config: const Oid4vciConfig(allowInsecureLoopback: true),
    );

    final req = await adapter.fetchRequest(server.launchUri('st_reject'));
    server.rejectPost = true;
    final rejectedOutcome = await adapter.presentCredential(
      request: req,
      credential: setup.cred,
    );
    expect(rejectedOutcome.state, PresentationState.rejected);

    final otherStore = MemoryHolderKeyStore();
    final mismatchAdapter = Oid4vpPresentationAdapter(
      keyStore: otherStore,
      config: const Oid4vciConfig(allowInsecureLoopback: true),
    );
    final mismatchOutcome = await mismatchAdapter.presentCredential(
      request: req,
      credential: setup.cred,
    );
    expect(mismatchOutcome.state, PresentationState.rejected);
  });
}
