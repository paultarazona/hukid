import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/crypto_jwe.dart';
import 'package:hukid_wallet/crypto_p256.dart';

Uint8List _fromHex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  test('aes256GcmEncrypt matches NIST SP 800-38D Test Case 16', () {
    final key = _fromHex(
      'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
    );
    final iv = _fromHex('cafebabefacedbaddecaf888');
    final plaintext = _fromHex(
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
      '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    );
    final aad = _fromHex('feedfacedeadbeeffeedfacedeadbeefabaddad2');

    final result = aes256GcmEncrypt(
      key: key,
      iv: iv,
      plaintext: plaintext,
      aad: aad,
    );

    expect(
      _toHex(result.ciphertext),
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa'
      '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662',
    );
    expect(_toHex(result.tag), '76fc6ece0f4e1768cddf8853bb2d551b');
  });

  test('P256 ECDH shared secret is symmetric between two key pairs', () {
    final alice = P256KeyPair.generate(kid: 'alice');
    final bob = P256KeyPair.generate(kid: 'bob');

    final zAlice = alice.ecdhSharedSecret(bob.publicJwk);
    final zBob = bob.ecdhSharedSecret(alice.publicJwk);

    expect(zAlice.length, 32);
    expect(zAlice, zBob);

    final cekAlice = concatKdfSha256(
      sharedSecret: zAlice,
      algorithmId: 'A256GCM',
      keyBits: 256,
    );
    final cekBob = concatKdfSha256(
      sharedSecret: zBob,
      algorithmId: 'A256GCM',
      keyBits: 256,
    );
    expect(cekAlice.length, 32);
    expect(cekAlice, cekBob);
  });

  test('encryptJweEcdhEsA256Gcm emits compact 5-part ECDH-ES A256GCM JWE', () {
    final recipient = P256KeyPair.generate(kid: 'sess-enc-1');
    final jwe = encryptJweEcdhEsA256Gcm(
      recipientKey: recipient.publicJwk,
      plaintext: utf8.encode('{"vp_token":{"cred":["vp"]},"state":"s1"}'),
    );

    final parts = jwe.split('.');
    expect(parts.length, 5);
    expect(parts[1], isEmpty); // Direct Key Agreement has empty encrypted key.

    final header = jsonDecode(
      utf8.decode(base64UrlNoPadDecode(parts[0])),
    ) as Map<String, dynamic>;
    expect(header['alg'], 'ECDH-ES');
    expect(header['enc'], 'A256GCM');
    expect(header['kid'], 'sess-enc-1');
    final epk = PublicEcJwk.fromJson(header['epk'] as Map<String, dynamic>);
    expect(epk.kty, 'EC');
    expect(epk.crv, 'P-256');
    expect(base64UrlNoPadDecode(parts[2]).length, 12);
    expect(base64UrlNoPadDecode(parts[4]).length, 16);
  });

  test('buildVerifiablePresentationJwt produces valid VCDM 2.0 vp+jwt', () async {
    final holder = P256KeyPair.generate();
    final vp = await buildVerifiablePresentationJwt(
      holderPublicJwk: holder.publicJwk,
      signEs256: (bytes) async => holder.signEs256(bytes),
      audience: 'x509_san_dns:hukid.zentrycore.com',
      nonce: 'nonce_123',
      credentials: const <String>['h.p.s'],
    );

    final parts = vp.split('.');
    expect(parts.length, 3);
    final header = jsonDecode(
      utf8.decode(base64UrlNoPadDecode(parts[0])),
    ) as Map<String, dynamic>;
    final payload = jsonDecode(
      utf8.decode(base64UrlNoPadDecode(parts[1])),
    ) as Map<String, dynamic>;

    expect(header['alg'], 'ES256');
    expect(header['typ'], 'vp+jwt');
    expect(
      PublicEcJwk.fromJson(header['jwk'] as Map<String, dynamic>).thumbprint(),
      holder.publicJwk.thumbprint(),
    );
    expect(payload['@context'], <String>[
      'https://www.w3.org/ns/credentials/v2',
      'https://schemas.hukid.pe/contexts/presentation/v1',
    ]);
    expect(payload['type'], <String>['VerifiablePresentation']);
    expect(payload['aud'], 'x509_san_dns:hukid.zentrycore.com');
    expect(payload['nonce'], 'nonce_123');
    final vcs = payload['verifiableCredential'] as List<dynamic>;
    expect(vcs.length, 1);
    final first = vcs.first as Map<String, dynamic>;
    expect(first['@context'], 'https://www.w3.org/ns/credentials/v2');
    expect(first['type'], 'EnvelopedVerifiableCredential');
    expect(first['id'], 'data:application/vc+jwt,h.p.s');
    expect(
      P256Curve.verifyEs256(
        holder.publicJwk,
        utf8.encode('${parts[0]}.${parts[1]}'),
        base64UrlNoPadDecode(parts[2]),
      ),
      isTrue,
    );
  });
}
