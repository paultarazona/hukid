import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/crypto_p256.dart';

String _toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  test('sha256Bytes matches FIPS 180-4 test vectors', () {
    expect(
      _toHex(sha256Bytes(utf8.encode(''))),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(
      _toHex(sha256Bytes(utf8.encode('abc'))),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(
      _toHex(
        sha256Bytes(
          utf8.encode(
            'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
          ),
        ),
      ),
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    );
  });

  test('P256KeyPair signs and verifies ES256 and detects tampering', () {
    final pair = P256KeyPair.generate();
    final msg = utf8.encode('hukid.oid4vci.test.message');
    final sig = pair.signEs256(msg);
    expect(sig.length, 64);
    expect(P256Curve.verifyEs256(pair.publicJwk, msg, sig), isTrue);

    final altered = Uint8List.fromList(sig);
    altered[0] ^= 0xff;
    expect(P256Curve.verifyEs256(pair.publicJwk, msg, altered), isFalse);
    expect(
      P256Curve.verifyEs256(
        pair.publicJwk,
        utf8.encode('tampered.message'),
        sig,
      ),
      isFalse,
    );
  });

  test('derToP1363 normalizes zero-padded and short ASN.1 DER signatures', () {
    final r32 = List<int>.generate(32, (i) => i + 1);
    final sShort = <int>[0x12, 0x34, 0x56];
    // Encode r with leading 0x00 and s with 3 bytes -> DER sequence length = 2 + 33 + 2 + 3 = 40.
    final der = Uint8List.fromList(<int>[
      0x30,
      40,
      0x02,
      33,
      0x00,
      ...r32,
      0x02,
      sShort.length,
      ...sShort,
    ]);
    final p1363 = derToP1363(der);
    expect(p1363.length, 64);
    expect(p1363.sublist(0, 32), r32);
    expect(p1363.sublist(32, 61), List<int>.filled(29, 0));
    expect(p1363.sublist(61, 64), sShort);

    expect(
      () => derToP1363(Uint8List.fromList(<int>[0x31, 2, 0x02, 0])),
      throwsFormatException,
    );
  });

  test('buildHolderProofJwt produces valid OID4VCI proof JWT', () async {
    final pair = P256KeyPair.generate();
    final jwt = await buildHolderProofJwt(
      publicJwk: pair.publicJwk,
      signEs256: (bytes) async => pair.signEs256(bytes),
      audience: 'https://issuer.hukid.pe/unas',
      nonce: 'nonce_abc_123',
      issuedAt: DateTime.utc(2026, 11, 20, 12, 0, 0),
    );
    final parts = jwt.split('.');
    expect(parts.length, 3);

    final header =
        jsonDecode(utf8.decode(base64UrlNoPadDecode(parts[0])))
            as Map<String, dynamic>;
    final payload =
        jsonDecode(utf8.decode(base64UrlNoPadDecode(parts[1])))
            as Map<String, dynamic>;
    expect(header['alg'], 'ES256');
    expect(header['typ'], oid4vciProofJwtType);
    final jwk = PublicEcJwk.fromJson(header['jwk'] as Map<String, dynamic>);
    expect(jwk.thumbprint(), pair.publicJwk.thumbprint());
    expect(payload['aud'], 'https://issuer.hukid.pe/unas');
    expect(payload['nonce'], 'nonce_abc_123');
    expect(payload['iat'], 1795176000);

    final sig = base64UrlNoPadDecode(parts[2]);
    expect(
      P256Curve.verifyEs256(
        jwk,
        utf8.encode('${parts[0]}.${parts[1]}'),
        sig,
      ),
      isTrue,
    );
  });
}
