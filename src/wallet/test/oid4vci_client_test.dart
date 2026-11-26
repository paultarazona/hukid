import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/crypto_p256.dart';
import 'package:hukid_wallet/issuance.dart';
import 'package:hukid_wallet/keystore.dart';
import 'package:hukid_wallet/oid4vci_client.dart';

class _MockHukidIssuer {
  _MockHukidIssuer(this._server, this._issuerKey)
    : origin = 'http://127.0.0.1:${_server.port}',
      issuerUri = 'http://127.0.0.1:${_server.port}/unas';

  final HttpServer _server;
  final P256KeyPair _issuerKey;
  final String origin;
  final String issuerUri;

  bool deferredMode = false;
  bool deferredDeny = false;
  bool tamperVcSignature = false;
  bool wrongHolderJkt = false;
  int deferredPollCount = 0;

  static Future<_MockHukidIssuer> start() async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final key = P256KeyPair.generate(kid: 'unas-k1');
    final mock = _MockHukidIssuer(server, key);
    server.listen(mock._handle);
    return mock;
  }

  Future<void> close() => _server.close(force: true);

  String _signVcJwt(String holderJkt) {
    final headerB64 = base64UrlNoPadEncode(
      utf8.encode(
        jsonEncode(<String, dynamic>{
          'alg': 'ES256',
          'typ': 'vc+jwt',
          'cty': 'vc',
          'kid': _issuerKey.publicJwk.kid,
        }),
      ),
    );
    final payloadB64 = base64UrlNoPadEncode(
      utf8.encode(
        jsonEncode(<String, dynamic>{
          '@context': <String>['https://www.w3.org/ns/credentials/v2'],
          'id': 'urn:uuid:11111111-1111-4111-8111-111111111111',
          'type': <String>[
            'VerifiableCredential',
            'EventParticipationCertificate',
          ],
          'issuer': issuerUri,
          'validFrom': '2026-11-20T00:00:00Z',
          'validUntil': '2027-11-20T00:00:00Z',
          'credentialSubject': <String, dynamic>{
            'participantName': 'Maria Quispe',
            'eventName': 'Congreso Cloud UNAS',
          },
          'cnf': <String, String>{
            'jkt': wrongHolderJkt ? 'wrong-jkt' : holderJkt,
          },
        }),
      ),
    );
    final signingInput = '$headerB64.$payloadB64';
    final sig = _issuerKey.signEs256(utf8.encode(signingInput));
    if (tamperVcSignature) {
      sig[5] ^= 0xff;
    }
    return '$signingInput.${base64UrlNoPadEncode(sig)}';
  }

  Future<void> _handle(HttpRequest req) async {
    final path = req.uri.path;
    final bodyText = await utf8.decoder.bind(req).join();

    if (req.method == 'GET' && path == '/unas/offers/ofr_123') {
      return _json(req.response, 200, <String, dynamic>{
        'credential_issuer': issuerUri,
        'credential_configuration_ids': <String>[
          'event_participation_v1',
        ],
        'grants': <String, dynamic>{
          preAuthorizedGrantType: <String, String>{
            'pre-authorized_code': 'preauth_secret_001',
          },
        },
      });
    }

    if (req.method == 'GET' && path == '/other/offers/bad') {
      return _json(req.response, 200, <String, dynamic>{
        'credential_issuer': issuerUri,
        'credential_configuration_ids': <String>['event_participation_v1'],
        'grants': <String, dynamic>{
          preAuthorizedGrantType: <String, String>{
            'pre-authorized_code': 'preauth_secret_001',
          },
        },
      });
    }

    if (req.method == 'GET' &&
        path == '/unas/.well-known/openid-credential-issuer') {
      return _json(req.response, 200, <String, dynamic>{
        'credential_issuer': issuerUri,
        'authorization_servers': <String>[origin],
        'credential_endpoint': '$issuerUri/credential',
        'deferred_credential_endpoint': '$issuerUri/deferred_credential',
        'nonce_endpoint': '$issuerUri/nonce',
        'credential_configurations_supported': <String, dynamic>{
          'event_participation_v1': <String, dynamic>{
            'format': 'vc+jwt',
            'cryptographic_binding_methods_supported': <String>['jwk'],
            'credential_signing_alg_values_supported': <String>['ES256'],
            'credential_definition': <String, dynamic>{
              'type': <String>[
                'VerifiableCredential',
                'EventParticipationCertificate',
              ],
            },
            'proof_types_supported': <String, dynamic>{
              'jwt': <String, dynamic>{
                'proof_signing_alg_values_supported': <String>['ES256'],
              },
            },
            'credential_metadata': <String, dynamic>{
              'display': <Map<String, String>>[
                <String, String>{
                  'name': 'Certificado de Participación',
                  'locale': 'es-PE',
                },
              ],
            },
          },
        },
      });
    }

    if (req.method == 'GET' &&
        path == '/.well-known/oauth-authorization-server') {
      return _json(req.response, 200, <String, dynamic>{
        'issuer': origin,
        'token_endpoint': '$origin/oauth2/token',
        'grant_types_supported': <String>[
          preAuthorizedGrantType,
          'client_credentials',
        ],
      });
    }

    if (req.method == 'POST' && path == '/oauth2/token') {
      final params = Uri.splitQueryString(bodyText);
      if (params['grant_type'] != preAuthorizedGrantType ||
          params['pre-authorized_code'] != 'preauth_secret_001') {
        return _json(req.response, 400, <String, String>{
          'error': 'invalid_grant',
        });
      }
      return _json(req.response, 200, <String, dynamic>{
        'access_token': 'vci_access_token_1',
        'token_type': 'Bearer',
        'expires_in': 300,
        'authorization_details': <Map<String, dynamic>>[
          <String, dynamic>{
            'type': 'openid_credential',
            'credential_configuration_id': 'event_participation_v1',
            'credential_identifiers': <String>['cred_req_1'],
          },
        ],
      });
    }

    if (req.method == 'POST' && path == '/unas/nonce') {
      return _json(req.response, 200, <String, String>{
        'c_nonce': 'cnonce_fresh_1',
      });
    }

    if (req.method == 'POST' && path == '/unas/credential') {
      if (req.headers.value(HttpHeaders.authorizationHeader) !=
          'Bearer vci_access_token_1') {
        return _json(req.response, 401, <String, String>{
          'error': 'invalid_token',
        });
      }
      final body = jsonDecode(bodyText) as Map<String, dynamic>;
      if (body['credential_identifier'] != 'cred_req_1') {
        return _json(req.response, 400, <String, String>{
          'error': 'unknown_credential_identifier',
        });
      }
      final proofs = body['proofs'] as Map<String, dynamic>;
      final jwtList = proofs['jwt'] as List<dynamic>;
      final proofJwt = jwtList.first as String;
      final parts = proofJwt.split('.');
      final hdr =
          jsonDecode(utf8.decode(base64UrlNoPadDecode(parts[0])))
              as Map<String, dynamic>;
      final pay =
          jsonDecode(utf8.decode(base64UrlNoPadDecode(parts[1])))
              as Map<String, dynamic>;
      if (hdr['alg'] != 'ES256' ||
          hdr['typ'] != oid4vciProofJwtType ||
          pay['aud'] != issuerUri ||
          pay['nonce'] != 'cnonce_fresh_1') {
        return _json(req.response, 400, <String, String>{
          'error': 'invalid_proof',
        });
      }
      final holderJwk = PublicEcJwk.fromJson(
        hdr['jwk'] as Map<String, dynamic>,
      );
      final validProof = P256Curve.verifyEs256(
        holderJwk,
        utf8.encode('${parts[0]}.${parts[1]}'),
        base64UrlNoPadDecode(parts[2]),
      );
      if (!validProof) {
        return _json(req.response, 400, <String, String>{
          'error': 'invalid_proof',
        });
      }

      if (deferredMode) {
        return _json(req.response, 202, <String, dynamic>{
          'transaction_id': 'tx_deferred_1',
          'interval': 1,
        });
      }
      return _json(req.response, 200, <String, dynamic>{
        'credentials': <Map<String, String>>[
          <String, String>{'credential': _signVcJwt(holderJwk.thumbprint())},
        ],
      });
    }

    if (req.method == 'POST' && path == '/unas/deferred_credential') {
      if (req.headers.value(HttpHeaders.authorizationHeader) !=
          'Bearer vci_access_token_1') {
        return _json(req.response, 401, <String, String>{
          'error': 'invalid_token',
        });
      }
      deferredPollCount++;
      if (deferredDeny) {
        return _json(req.response, 400, <String, String>{
          'error': 'credential_request_denied',
        });
      }
      if (deferredPollCount == 1) {
        return _json(req.response, 400, <String, dynamic>{
          'error': 'issuance_pending',
          'interval': 1,
        });
      }
      final keyStoreHolderJkt = _lastHolderJkt;
      return _json(req.response, 200, <String, dynamic>{
        'credentials': <Map<String, String>>[
          <String, String>{'credential': _signVcJwt(keyStoreHolderJkt!)},
        ],
      });
    }

    if (req.method == 'GET' && path == '/unas/.well-known/jwks.json') {
      final jwk = _issuerKey.publicJwk;
      return _json(req.response, 200, <String, dynamic>{
        'keys': <Map<String, dynamic>>[
          <String, dynamic>{
            'kty': 'EC',
            'crv': 'P-256',
            'x': jwk.x,
            'y': jwk.y,
            'kid': jwk.kid,
            'alg': 'ES256',
            'use': 'sig',
          },
        ],
      });
    }

    req.response.statusCode = 404;
    await req.response.close();
  }

  String? _lastHolderJkt;

  Future<void> _json(
    HttpResponse res,
    int status,
    Map<String, dynamic> body,
  ) async {
    res.statusCode = status;
    res.headers.contentType = ContentType.json;
    res.write(jsonEncode(body));
    await res.close();
  }
}

void main() {
  test('immediate OID4VCI flow verifies JWKS signature and stores VC', () async {
    final server = await _MockHukidIssuer.start();
    addTearDown(server.close);

    final keyStore = MemoryHolderKeyStore();
    final vault = MemoryCredentialVault();
    final adapter = Oid4vciOfferAdapter(
      keyStore: keyStore,
      vault: vault,
      config: const Oid4vciConfig(allowInsecureLoopback: true),
    );
    final flow = Issuance(adapter);
    final link =
        'openid-credential-offer://?credential_offer_uri=${Uri.encodeQueryComponent('${server.issuerUri}/offers/ofr_123')}';

    await flow.preview(link);
    expect(flow.state, ReceiptState.preview);
    expect(flow.offer?.title, 'Certificado de Participación');

    await flow.receive(consent: true);
    expect(flow.state, ReceiptState.stored);
    expect(flow.credential, isNotNull);

    final storedList = await vault.listCredentials();
    expect(storedList.length, 1);
    expect(storedList.first.configurationId, 'event_participation_v1');
    expect(storedList.first.credentialIssuer, server.issuerUri);
  });

  test('deferred OID4VCI flow polls issuance_pending until vc+jwt stored', () async {
    final server = await _MockHukidIssuer.start();
    server.deferredMode = true;
    addTearDown(server.close);

    final keyStore = MemoryHolderKeyStore();
    final vault = MemoryCredentialVault();
    final holderJwk = await keyStore.ensureKey(
      safeVaultId('hukid_key', server.issuerUri),
    );
    server._lastHolderJkt = holderJwk.thumbprint();

    final adapter = Oid4vciOfferAdapter(
      keyStore: keyStore,
      vault: vault,
      config: const Oid4vciConfig(allowInsecureLoopback: true),
    );
    final flow = Issuance(adapter);
    final link =
        'openid-credential-offer://?credential_offer_uri=${Uri.encodeQueryComponent('${server.issuerUri}/offers/ofr_123')}';

    await flow.preview(link);
    await flow.receive(consent: true);
    expect(flow.state, ReceiptState.pending);
    expect(flow.deferred?.transactionId, 'tx_deferred_1');
    expect((await vault.listPendingDeferred()).length, 1);

    await flow.pollPending();
    expect(flow.state, ReceiptState.pending);
    expect((await vault.listCredentials()), isEmpty);

    await flow.pollPending();
    expect(flow.state, ReceiptState.stored);
    expect((await vault.listPendingDeferred()), isEmpty);
    expect((await vault.listCredentials()).length, 1);
  });

  test('fails closed on tampered VC signature, wrong cnf.jkt, HTTP prod & origin mismatch', () async {
    final server = await _MockHukidIssuer.start();
    addTearDown(server.close);

    final link =
        'openid-credential-offer://?credential_offer_uri=${Uri.encodeQueryComponent('${server.issuerUri}/offers/ofr_123')}';

    // 1. Default config rejects plain HTTP even on loopback.
    final strictFlow = Issuance(
      Oid4vciOfferAdapter(
        keyStore: MemoryHolderKeyStore(),
        vault: MemoryCredentialVault(),
      ),
    );
    await strictFlow.preview(link);
    expect(strictFlow.state, ReceiptState.unavailable);

    // 2. Offer path outside issuer prefix fails closed.
    final keyStore = MemoryHolderKeyStore();
    final vault = MemoryCredentialVault();
    final flow = Issuance(
      Oid4vciOfferAdapter(
        keyStore: keyStore,
        vault: vault,
        config: const Oid4vciConfig(allowInsecureLoopback: true),
      ),
    );
    await flow.preview(
      'openid-credential-offer://?credential_offer_uri=${Uri.encodeQueryComponent('${server.origin}/other/offers/bad')}',
    );
    expect(flow.state, ReceiptState.unavailable);

    // 3. Tampered VC signature never saves to vault.
    server.tamperVcSignature = true;
    await flow.preview(link);
    expect(flow.state, ReceiptState.preview);
    await flow.receive(consent: true);
    expect(flow.state, ReceiptState.unavailable);
    expect((await vault.listCredentials()), isEmpty);

    // 4. Wrong cnf.jkt binding never saves to vault.
    server.tamperVcSignature = false;
    server.wrongHolderJkt = true;
    await flow.preview(link);
    await flow.receive(consent: true);
    expect(flow.state, ReceiptState.unavailable);
    expect((await vault.listCredentials()), isEmpty);
  });

  test('deferred denial deletes pending record from vault', () async {
    final server = await _MockHukidIssuer.start();
    server.deferredMode = true;
    server.deferredDeny = true;
    addTearDown(server.close);

    final vault = MemoryCredentialVault();
    final flow = Issuance(
      Oid4vciOfferAdapter(
        keyStore: MemoryHolderKeyStore(),
        vault: vault,
        config: const Oid4vciConfig(allowInsecureLoopback: true),
      ),
    );
    final link =
        'openid-credential-offer://?credential_offer_uri=${Uri.encodeQueryComponent('${server.issuerUri}/offers/ofr_123')}';

    await flow.preview(link);
    await flow.receive(consent: true);
    expect(flow.state, ReceiptState.pending);
    expect((await vault.listPendingDeferred()).length, 1);

    await flow.pollPending();
    expect(flow.state, ReceiptState.unavailable);
    expect((await vault.listPendingDeferred()), isEmpty);
  });
}
