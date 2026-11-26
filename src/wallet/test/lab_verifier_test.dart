import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/crypto_p256.dart';
import 'package:hukid_wallet/lab_verifier.dart';

void main() {
  final key = P256KeyPair.generate(kid: 'lab-1').publicJwk;
  final jwk = base64.encode(utf8.encode(jsonEncode({'kty': 'EC', 'crv': 'P-256', 'x': key.x, 'y': key.y, 'kid': 'lab-1'})));
  final ca = base64.encode(utf8.encode('pem'));
  LabVerifierTrust? parse({bool lab = true, String? k, String? c, String origin = 'https://127.0.0.1:8443'}) =>
      LabVerifierTrust.parse(labEnabled: lab, jwkBase64: k ?? jwk, caBase64: c ?? ca, origin: origin);

  test('lab trust needs the lab flag, complete data and a loopback https origin', () {
    expect(parse()!.signingKeys.keys, ['lab-1']);
    expect(parse(lab: false), isNull);
    expect(parse(k: ''), isNull);
    expect(parse(c: ''), isNull);
    expect(parse(k: 'no-es-base64!'), isNull);
    expect(parse(origin: 'http://127.0.0.1:8443'), isNull);
    expect(parse(origin: 'https://example.com:8443'), isNull);
  });
}
