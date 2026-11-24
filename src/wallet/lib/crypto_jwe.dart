import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'crypto_p256.dart';

/// Ciphertext and 16-byte authentication tag produced by AES-256-GCM.
class AesGcmResult {
  const AesGcmResult({required this.ciphertext, required this.tag});

  final Uint8List ciphertext;
  final Uint8List tag;
}

const List<int> _aesSbox = <int>[
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const List<int> _aesRcon = <int>[0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

int _xtime(int b) => ((b << 1) ^ ((b & 0x80) != 0 ? 0x1b : 0)) & 0xff;

class _Aes256 {
  _Aes256(Uint8List key) : _roundKeys = _expandKey(key);

  final Uint8List _roundKeys;

  static Uint8List _expandKey(Uint8List key) {
    if (key.length != 32) {
      throw ArgumentError('AES-256 requires a 32-byte key');
    }
    final expanded = Uint8List(240);
    expanded.setRange(0, 32, key);
    final temp = Uint8List(4);
    var offset = 32;
    var rconIdx = 1;
    while (offset < 240) {
      temp.setRange(0, 4, expanded, offset - 4);
      final wordIdx = offset ~/ 4;
      if (wordIdx % 8 == 0) {
        final t0 = temp[0];
        temp[0] = _aesSbox[temp[1]] ^ _aesRcon[rconIdx++];
        temp[1] = _aesSbox[temp[2]];
        temp[2] = _aesSbox[temp[3]];
        temp[3] = _aesSbox[t0];
      } else if (wordIdx % 8 == 4) {
        for (var j = 0; j < 4; j++) {
          temp[j] = _aesSbox[temp[j]];
        }
      }
      for (var j = 0; j < 4; j++) {
        expanded[offset + j] = expanded[offset - 32 + j] ^ temp[j];
      }
      offset += 4;
    }
    return expanded;
  }

  Uint8List encryptBlock(Uint8List block) {
    if (block.length != 16) {
      throw ArgumentError('AES block must be 16 bytes');
    }
    final s = Uint8List.fromList(block);
    _addRoundKey(s, 0);
    for (var round = 1; round < 14; round++) {
      _subBytes(s);
      _shiftRows(s);
      _mixColumns(s);
      _addRoundKey(s, round * 16);
    }
    _subBytes(s);
    _shiftRows(s);
    _addRoundKey(s, 14 * 16);
    return s;
  }

  void _addRoundKey(Uint8List s, int rkOffset) {
    for (var i = 0; i < 16; i++) {
      s[i] ^= _roundKeys[rkOffset + i];
    }
  }

  void _subBytes(Uint8List s) {
    for (var i = 0; i < 16; i++) {
      s[i] = _aesSbox[s[i]];
    }
  }

  void _shiftRows(Uint8List s) {
    var t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;

    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;

    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
  }

  void _mixColumns(Uint8List s) {
    for (var col = 0; col < 16; col += 4) {
      final a0 = s[col];
      final a1 = s[col + 1];
      final a2 = s[col + 2];
      final a3 = s[col + 3];
      final x0 = _xtime(a0);
      final x1 = _xtime(a1);
      final x2 = _xtime(a2);
      final x3 = _xtime(a3);
      s[col] = x0 ^ (x1 ^ a1) ^ a2 ^ a3;
      s[col + 1] = a0 ^ x1 ^ (x2 ^ a2) ^ a3;
      s[col + 2] = a0 ^ a1 ^ x2 ^ (x3 ^ a3);
      s[col + 3] = (x0 ^ a0) ^ a1 ^ a2 ^ x3;
    }
  }
}

Uint8List _gfMul(Uint8List x, Uint8List y) {
  final z = Uint8List(16);
  final v = Uint8List.fromList(y);
  for (var i = 0; i < 128; i++) {
    if ((x[i >> 3] & (0x80 >> (i & 7))) != 0) {
      for (var j = 0; j < 16; j++) {
        z[j] ^= v[j];
      }
    }
    final lsb = v[15] & 1;
    for (var j = 15; j > 0; j--) {
      v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
    }
    v[0] >>= 1;
    if (lsb != 0) {
      v[0] ^= 0xe1;
    }
  }
  return z;
}

void _inc32(Uint8List counterBlock) {
  for (var i = 15; i >= 12; i--) {
    final next = (counterBlock[i] + 1) & 0xff;
    counterBlock[i] = next;
    if (next != 0) break;
  }
}

Uint8List _ghash(Uint8List h, Uint8List aad, Uint8List ciphertext) {
  var y = Uint8List(16);
  final block = Uint8List(16);

  void processPadded(Uint8List data) {
    for (var offset = 0; offset < data.length; offset += 16) {
      block.fillRange(0, 16, 0);
      final end = offset + 16 <= data.length ? offset + 16 : data.length;
      block.setRange(0, end - offset, data, offset);
      for (var i = 0; i < 16; i++) {
        y[i] ^= block[i];
      }
      y = _gfMul(y, h);
    }
  }

  processPadded(aad);
  processPadded(ciphertext);

  final aadBits = aad.length * 8;
  final ctBits = ciphertext.length * 8;
  final lenBlock = Uint8List(16);
  final lenData = ByteData.sublistView(lenBlock);
  lenData.setUint32(0, aadBits ~/ 0x100000000, Endian.big);
  lenData.setUint32(4, aadBits & 0xffffffff, Endian.big);
  lenData.setUint32(8, ctBits ~/ 0x100000000, Endian.big);
  lenData.setUint32(12, ctBits & 0xffffffff, Endian.big);
  for (var i = 0; i < 16; i++) {
    y[i] ^= lenBlock[i];
  }
  return _gfMul(y, h);
}

/// Encrypts [plaintext] using AES-256-GCM (NIST SP 800-38D) with a 96-bit [iv].
AesGcmResult aes256GcmEncrypt({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List plaintext,
  required Uint8List aad,
}) {
  if (key.length != 32) {
    throw ArgumentError('AES-256-GCM requires a 32-byte key');
  }
  if (iv.length != 12) {
    throw ArgumentError('AES-256-GCM requires a 12-byte IV');
  }
  final aes = _Aes256(key);
  final h = aes.encryptBlock(Uint8List(16));

  final j0 = Uint8List(16);
  j0.setRange(0, 12, iv);
  j0[15] = 1;

  final cb = Uint8List.fromList(j0);
  _inc32(cb);
  final ciphertext = Uint8List(plaintext.length);
  for (var offset = 0; offset < plaintext.length; offset += 16) {
    final keystream = aes.encryptBlock(cb);
    _inc32(cb);
    final end = offset + 16 <= plaintext.length ? offset + 16 : plaintext.length;
    for (var i = offset; i < end; i++) {
      ciphertext[i] = plaintext[i] ^ keystream[i - offset];
    }
  }

  final s = _ghash(h, aad, ciphertext);
  final tagMask = aes.encryptBlock(j0);
  final tag = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    tag[i] = s[i] ^ tagMask[i];
  }
  return AesGcmResult(ciphertext: ciphertext, tag: tag);
}

/// NIST SP 800-56A Concat KDF (SHA-256) for JWA ECDH-ES (RFC 7518 Section 4.6.2).
Uint8List concatKdfSha256({
  required Uint8List sharedSecret,
  required String algorithmId,
  int keyBits = 256,
}) {
  if (keyBits != 256) {
    throw ArgumentError('only 256-bit derived keys are supported');
  }
  final algBytes = ascii.encode(algorithmId);
  final buf = BytesBuilder(copy: false);
  final u32 = Uint8List(4);
  final view = ByteData.sublistView(u32);

  void addUint32(int value) {
    view.setUint32(0, value, Endian.big);
    buf.add(Uint8List.fromList(u32));
  }

  addUint32(1);
  buf.add(sharedSecret);
  addUint32(algBytes.length);
  buf.add(algBytes);
  addUint32(0); // PartyUInfo length
  addUint32(0); // PartyVInfo length
  addUint32(keyBits); // SuppPubInfo
  return sha256Bytes(buf.takeBytes());
}

/// Encrypts [plaintext] into a compact JWE (`alg=ECDH-ES`, `enc=A256GCM`) for
/// [recipientKey], carrying the ephemeral P-256 public key in header `epk`.
String encryptJweEcdhEsA256Gcm({
  required PublicEcJwk recipientKey,
  required Uint8List plaintext,
  Uint8List? ivOverride,
  P256KeyPair? ephemeralKeyOverride,
}) {
  final kid = recipientKey.kid;
  if (kid == null || kid.isEmpty) {
    throw ArgumentError('recipient JWK must include a non-empty kid');
  }
  final epk = ephemeralKeyOverride ?? P256KeyPair.generate();
  final sharedSecret = epk.ecdhSharedSecret(recipientKey);
  final cek = concatKdfSha256(
    sharedSecret: sharedSecret,
    algorithmId: 'A256GCM',
    keyBits: 256,
  );

  final protectedHeader = <String, dynamic>{
    'alg': 'ECDH-ES',
    'enc': 'A256GCM',
    'kid': kid,
    'epk': epk.publicJwk.toProofHeaderJwk(),
  };
  final protectedB64 = base64UrlNoPadEncode(
    utf8.encode(jsonEncode(protectedHeader)),
  );
  final aad = Uint8List.fromList(ascii.encode(protectedB64));

  late final Uint8List iv;
  if (ivOverride != null) {
    if (ivOverride.length != 12) {
      throw ArgumentError('ivOverride must be 12 bytes');
    }
    iv = Uint8List.fromList(ivOverride);
  } else {
    final rng = Random.secure();
    iv = Uint8List.fromList(List<int>.generate(12, (_) => rng.nextInt(256)));
  }

  final encrypted = aes256GcmEncrypt(
    key: cek,
    iv: iv,
    plaintext: plaintext,
    aad: aad,
  );

  return '$protectedB64..${base64UrlNoPadEncode(iv)}.'
      '${base64UrlNoPadEncode(encrypted.ciphertext)}.'
      '${base64UrlNoPadEncode(encrypted.tag)}';
}
