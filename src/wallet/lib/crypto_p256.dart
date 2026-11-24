import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

const String oid4vciProofJwtType = 'openid4vci-proof+jwt';
const String oid4vpPresentationJwtType = 'vp+jwt';
const String vcdmBaseContext = 'https://www.w3.org/ns/credentials/v2';
const String hukidPresentationContext =
    'https://schemas.hukid.pe/contexts/presentation/v1';

Uint8List _u32FractionBits(int prime, double rootExponent) {
  final val = pow(prime.toDouble(), rootExponent).toDouble();
  final frac = val - val.floorToDouble();
  final scaled = (frac * 4294967296.0).floor();
  final out = Uint8List(4);
  ByteData.sublistView(out).setUint32(0, scaled & 0xffffffff, Endian.big);
  return out;
}

final List<int> _first64Primes = _computePrimes(64);
final Uint32List _sha256Init = Uint32List.fromList([
  for (var i = 0; i < 8; i++)
    ByteData.sublistView(_u32FractionBits(_first64Primes[i], 0.5)).getUint32(0),
]);
final Uint32List _sha256RoundK = Uint32List.fromList([
  for (var i = 0; i < 64; i++)
    ByteData.sublistView(
      _u32FractionBits(_first64Primes[i], 1.0 / 3.0),
    ).getUint32(0),
]);

List<int> _computePrimes(int count) {
  final primes = <int>[];
  var candidate = 2;
  while (primes.length < count) {
    var prime = true;
    for (final p in primes) {
      if (p * p > candidate) break;
      if (candidate % p == 0) {
        prime = false;
        break;
      }
    }
    if (prime) primes.add(candidate);
    candidate++;
  }
  return primes;
}

int _rotr32(int value, int shift) =>
    ((value & 0xffffffff) >>> shift) | ((value << (32 - shift)) & 0xffffffff);

/// Computes a standard 32-byte SHA-256 digest of [input].
Uint8List sha256Bytes(List<int> input) {
  final bitLength = input.length * 8;
  final padZeroCount = (55 - (input.length % 64) + 64) % 64;
  final padded = Uint8List(input.length + 1 + padZeroCount + 8);
  padded.setRange(0, input.length, input);
  padded[input.length] = 0x80;
  ByteData.sublistView(padded).setUint64(padded.length - 8, bitLength, Endian.big);

  final h = Uint32List.fromList(_sha256Init);
  final w = Uint32List(64);
  final data = ByteData.sublistView(padded);

  for (var chunk = 0; chunk < padded.length; chunk += 64) {
    for (var i = 0; i < 16; i++) {
      w[i] = data.getUint32(chunk + i * 4, Endian.big);
    }
    for (var i = 16; i < 64; i++) {
      final s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      final s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
    }

    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];
    var f = h[5];
    var g = h[6];
    var hh = h[7];

    for (var i = 0; i < 64; i++) {
      final s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25);
      final ch = (e & f) ^ ((~e & 0xffffffff) & g);
      final temp1 = (hh + s1 + ch + _sha256RoundK[i] + w[i]) & 0xffffffff;
      final s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final temp2 = (s0 + maj) & 0xffffffff;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xffffffff;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xffffffff;
    }

    h[0] = (h[0] + a) & 0xffffffff;
    h[1] = (h[1] + b) & 0xffffffff;
    h[2] = (h[2] + c) & 0xffffffff;
    h[3] = (h[3] + d) & 0xffffffff;
    h[4] = (h[4] + e) & 0xffffffff;
    h[5] = (h[5] + f) & 0xffffffff;
    h[6] = (h[6] + g) & 0xffffffff;
    h[7] = (h[7] + hh) & 0xffffffff;
  }

  final digest = Uint8List(32);
  final outData = ByteData.sublistView(digest);
  for (var i = 0; i < 8; i++) {
    outData.setUint32(i * 4, h[i], Endian.big);
  }
  return digest;
}

String base64UrlNoPadEncode(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

Uint8List base64UrlNoPadDecode(String encoded) {
  if (encoded.isEmpty || encoded.contains('=')) {
    throw const FormatException('invalid unpadded base64url');
  }
  final normalized = base64Url.normalize(encoded);
  return Uint8List.fromList(base64Url.decode(normalized));
}

/// Converts an ASN.1 DER ECDSA signature into a 64-byte IEEE P1363 `r || s`.
Uint8List derToP1363(Uint8List der) {
  if (der.length < 8 || der[0] != 0x30) {
    throw const FormatException('invalid DER signature sequence');
  }
  final seqHeader = _readDerLength(der, 1);
  var idx = seqHeader.nextOffset;
  if (idx + seqHeader.length != der.length) {
    throw const FormatException('invalid DER sequence length');
  }
  if (idx >= der.length || der[idx++] != 0x02) {
    throw const FormatException('expected INTEGER r');
  }
  final rLen = _readDerLength(der, idx);
  idx = rLen.nextOffset;
  if (rLen.length <= 0 || idx + rLen.length > der.length) {
    throw const FormatException('invalid INTEGER r length');
  }
  final rSlice = der.sublist(idx, idx + rLen.length);
  idx += rLen.length;

  if (idx >= der.length || der[idx++] != 0x02) {
    throw const FormatException('expected INTEGER s');
  }
  final sLen = _readDerLength(der, idx);
  idx = sLen.nextOffset;
  if (sLen.length <= 0 || idx + sLen.length != der.length) {
    throw const FormatException('invalid INTEGER s length');
  }
  final sSlice = der.sublist(idx, idx + sLen.length);

  final out = Uint8List(64);
  _copyScalar32(rSlice, out, 0);
  _copyScalar32(sSlice, out, 32);
  return out;
}

class _DerLength {
  const _DerLength(this.length, this.nextOffset);
  final int length;
  final int nextOffset;
}

_DerLength _readDerLength(Uint8List buf, int offset) {
  if (offset >= buf.length) throw const FormatException('truncated DER length');
  final first = buf[offset];
  if (first < 0x80) return _DerLength(first, offset + 1);
  final count = first & 0x7f;
  if (count == 0 || count > 2 || offset + 1 + count > buf.length) {
    throw const FormatException('unsupported DER length');
  }
  var len = 0;
  for (var i = 0; i < count; i++) {
    len = (len << 8) | buf[offset + 1 + i];
  }
  return _DerLength(len, offset + 1 + count);
}

void _copyScalar32(Uint8List src, Uint8List dst, int dstOffset) {
  if ((src[0] & 0x80) != 0) {
    throw const FormatException('negative DER integer');
  }
  var start = 0;
  while (start < src.length - 1 && src[start] == 0) {
    start++;
  }
  final len = src.length - start;
  if (len > 32) {
    throw const FormatException('ECDSA integer exceeds 32 bytes');
  }
  dst.setRange(dstOffset + (32 - len), dstOffset + 32, src, start);
}

BigInt _bytesToBigInt(List<int> bytes) {
  var acc = BigInt.zero;
  for (final b in bytes) {
    acc = (acc << 8) | BigInt.from(b & 0xff);
  }
  return acc;
}

Uint8List _bigIntTo32Bytes(BigInt value) {
  if (value.isNegative) {
    throw ArgumentError('negative coordinate');
  }
  final out = Uint8List(32);
  var cur = value;
  for (var i = 31; i >= 0; i--) {
    out[i] = (cur & BigInt.from(0xff)).toInt();
    cur = cur >> 8;
  }
  if (cur != BigInt.zero) {
    throw ArgumentError('value exceeds 256 bits');
  }
  return out;
}

/// Public EC P-256 JWK supporting RFC 7638 thumbprint calculation.
class PublicEcJwk {
  const PublicEcJwk({
    required this.x,
    required this.y,
    this.kid,
  });

  final String x;
  final String y;
  final String? kid;

  String get kty => 'EC';
  String get crv => 'P-256';

  factory PublicEcJwk.fromPoint(BigInt xCoord, BigInt yCoord, {String? kid}) {
    if (!P256Curve.isOnCurve(xCoord, yCoord)) {
      throw const FormatException('point is not on P-256');
    }
    return PublicEcJwk(
      x: base64UrlNoPadEncode(_bigIntTo32Bytes(xCoord)),
      y: base64UrlNoPadEncode(_bigIntTo32Bytes(yCoord)),
      kid: kid,
    );
  }

  factory PublicEcJwk.fromJson(Map<String, dynamic> json) {
    final kty = json['kty'];
    final crv = json['crv'];
    final x = json['x'];
    final y = json['y'];
    final kid = json['kid'];
    if (kty != 'EC' ||
        crv != 'P-256' ||
        x is! String ||
        y is! String ||
        (kid != null && kid is! String)) {
      throw const FormatException('invalid EC P-256 JWK');
    }
    final xBytes = base64UrlNoPadDecode(x);
    final yBytes = base64UrlNoPadDecode(y);
    if (xBytes.length != 32 || yBytes.length != 32) {
      throw const FormatException('invalid coordinate length');
    }
    final xVal = _bytesToBigInt(xBytes);
    final yVal = _bytesToBigInt(yBytes);
    if (!P256Curve.isOnCurve(xVal, yVal)) {
      throw const FormatException('JWK point not on P-256');
    }
    return PublicEcJwk(x: x, y: y, kid: kid as String?);
  }

  BigInt get xBigInt => _bytesToBigInt(base64UrlNoPadDecode(x));
  BigInt get yBigInt => _bytesToBigInt(base64UrlNoPadDecode(y));

  Map<String, String> toProofHeaderJwk() => <String, String>{
    'kty': 'EC',
    'crv': 'P-256',
    'x': x,
    'y': y,
  };

  /// Computes RFC 7638 canonical SHA-256 JWK thumbprint (matches `cnf.jkt`).
  String thumbprint() {
    final canonical = jsonEncode(<String, String>{
      'crv': 'P-256',
      'kty': 'EC',
      'x': x,
      'y': y,
    });
    return base64UrlNoPadEncode(sha256Bytes(utf8.encode(canonical)));
  }
}

class _JacobianPoint {
  const _JacobianPoint(this.x, this.y, this.z);
  final BigInt x;
  final BigInt y;
  final BigInt z;

  static final _JacobianPoint infinity =
      _JacobianPoint(BigInt.zero, BigInt.one, BigInt.zero);

  bool get isInfinity => z == BigInt.zero;
}

class _AffinePoint {
  const _AffinePoint(this.x, this.y);
  final BigInt x;
  final BigInt y;
}

/// NIST P-256 (secp256r1) elliptic curve arithmetic and ES256 operations.
class P256Curve {
  static final BigInt p = BigInt.parse(
    'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
    radix: 16,
  );
  static final BigInt n = BigInt.parse(
    'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    radix: 16,
  );
  static final BigInt halfN = n >> 1;
  static final BigInt b = BigInt.parse(
    '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
    radix: 16,
  );
  static final BigInt gx = BigInt.parse(
    '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
    radix: 16,
  );
  static final BigInt gy = BigInt.parse(
    '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
    radix: 16,
  );

  static BigInt _modP(BigInt v) {
    final res = v % p;
    return res.isNegative ? res + p : res;
  }

  static BigInt _modN(BigInt v) {
    final res = v % n;
    return res.isNegative ? res + n : res;
  }

  static bool isOnCurve(BigInt x, BigInt y) {
    if (x.isNegative || y.isNegative || x >= p || y >= p) return false;
    final lhs = _modP(y * y);
    final rhs = _modP(x * x * x - BigInt.from(3) * x + b);
    return lhs == rhs;
  }

  static _JacobianPoint _double(_JacobianPoint pt) {
    if (pt.isInfinity || pt.y == BigInt.zero) return _JacobianPoint.infinity;
    final zz = _modP(pt.z * pt.z);
    final yy = _modP(pt.y * pt.y);
    final yyyy = _modP(yy * yy);
    final s = _modP(BigInt.from(4) * pt.x * yy);
    final m = _modP(BigInt.from(3) * (pt.x - zz) * (pt.x + zz));
    final x3 = _modP(m * m - BigInt.from(2) * s);
    final y3 = _modP(m * (s - x3) - BigInt.from(8) * yyyy);
    final z3 = _modP(BigInt.from(2) * pt.y * pt.z);
    return _JacobianPoint(x3, y3, z3);
  }

  static _JacobianPoint _add(_JacobianPoint p1, _JacobianPoint p2) {
    if (p1.isInfinity) return p2;
    if (p2.isInfinity) return p1;
    final z1z1 = _modP(p1.z * p1.z);
    final z2z2 = _modP(p2.z * p2.z);
    final u1 = _modP(p1.x * z2z2);
    final u2 = _modP(p2.x * z1z1);
    final s1 = _modP(p1.y * p2.z * z2z2);
    final s2 = _modP(p2.y * p1.z * z1z1);
    if (u1 == u2) {
      if (s1 != s2) return _JacobianPoint.infinity;
      return _double(p1);
    }
    final h = _modP(u2 - u1);
    final r = _modP(s2 - s1);
    final hh = _modP(h * h);
    final hhh = _modP(h * hh);
    final v = _modP(u1 * hh);
    final x3 = _modP(r * r - hhh - BigInt.from(2) * v);
    final y3 = _modP(r * (v - x3) - s1 * hhh);
    final z3 = _modP(h * p1.z * p2.z);
    return _JacobianPoint(x3, y3, z3);
  }

  static _AffinePoint? _scalarMul(BigInt scalar, BigInt px, BigInt py) {
    final k = _modN(scalar);
    if (k == BigInt.zero) return null;
    final base = _JacobianPoint(px, py, BigInt.one);
    var acc = _JacobianPoint.infinity;
    for (var bit = k.bitLength - 1; bit >= 0; bit--) {
      acc = _double(acc);
      if ((k & (BigInt.one << bit)) != BigInt.zero) {
        acc = _add(acc, base);
      }
    }
    if (acc.isInfinity) return null;
    final zInv = acc.z.modInverse(p);
    final zInv2 = _modP(zInv * zInv);
    final zInv3 = _modP(zInv2 * zInv);
    return _AffinePoint(_modP(acc.x * zInv2), _modP(acc.y * zInv3));
  }

  static BigInt _randomScalar(Random rng) {
    while (true) {
      final bytes = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        bytes[i] = rng.nextInt(256);
      }
      final candidate = _bytesToBigInt(bytes);
      if (candidate > BigInt.zero && candidate < n) {
        return candidate;
      }
    }
  }

  static bool verifyEs256(
    PublicEcJwk key,
    List<int> message,
    Uint8List signature64,
  ) {
    if (signature64.length != 64) return false;
    final r = _bytesToBigInt(signature64.sublist(0, 32));
    final s = _bytesToBigInt(signature64.sublist(32, 64));
    if (r <= BigInt.zero || r >= n || s <= BigInt.zero || s >= n) return false;

    final qx = key.xBigInt;
    final qy = key.yBigInt;
    if (!isOnCurve(qx, qy)) return false;

    final e = _bytesToBigInt(sha256Bytes(message));
    final w = s.modInverse(n);
    final u1 = _modN(e * w);
    final u2 = _modN(r * w);

    final p1 = _scalarMulAffineJacobian(u1, gx, gy);
    final p2 = _scalarMulAffineJacobian(u2, qx, qy);
    final sum = _add(p1, p2);
    if (sum.isInfinity) return false;

    final zInv = sum.z.modInverse(p);
    final x = _modP(sum.x * zInv * zInv);
    return _modN(x) == r;
  }

  /// Computes the 32-byte big-endian X-coordinate ECDH shared secret Z
  /// between [privateKey] and [peerPublicKey] on NIST P-256.
  static Uint8List ecdhSharedSecret(
    BigInt privateKey,
    PublicEcJwk peerPublicKey,
  ) {
    if (privateKey <= BigInt.zero || privateKey >= n) {
      throw ArgumentError('ECDH private scalar out of range');
    }
    final peerX = peerPublicKey.xBigInt;
    final peerY = peerPublicKey.yBigInt;
    if (!isOnCurve(peerX, peerY)) {
      throw const FormatException('peer public key is not on P-256');
    }
    final shared = _scalarMul(privateKey, peerX, peerY);
    if (shared == null || !isOnCurve(shared.x, shared.y)) {
      throw StateError('ECDH produced point at infinity');
    }
    return _bigIntTo32Bytes(shared.x);
  }

  static _JacobianPoint _scalarMulAffineJacobian(
    BigInt scalar,
    BigInt px,
    BigInt py,
  ) {
    final k = _modN(scalar);
    if (k == BigInt.zero) return _JacobianPoint.infinity;
    final base = _JacobianPoint(px, py, BigInt.one);
    var acc = _JacobianPoint.infinity;
    for (var bit = k.bitLength - 1; bit >= 0; bit--) {
      acc = _double(acc);
      if ((k & (BigInt.one << bit)) != BigInt.zero) {
        acc = _add(acc, base);
      }
    }
    return acc;
  }
}

/// Software ECDSA P-256 key pair used by in-memory tests and cross-platform fallbacks.
class P256KeyPair {
  P256KeyPair._(this._d, this.publicJwk);

  final BigInt _d;
  final PublicEcJwk publicJwk;

  factory P256KeyPair.generate({Random? random, String? kid}) {
    final rng = random ?? Random.secure();
    while (true) {
      final d = P256Curve._randomScalar(rng);
      final pt = P256Curve._scalarMul(d, P256Curve.gx, P256Curve.gy);
      if (pt != null && P256Curve.isOnCurve(pt.x, pt.y)) {
        return P256KeyPair._(d, PublicEcJwk.fromPoint(pt.x, pt.y, kid: kid));
      }
    }
  }

  factory P256KeyPair.fromPrivateBytes(List<int> privateBytes, {String? kid}) {
    if (privateBytes.length != 32) {
      throw ArgumentError('P-256 private scalar must be 32 bytes');
    }
    final d = _bytesToBigInt(privateBytes);
    if (d <= BigInt.zero || d >= P256Curve.n) {
      throw ArgumentError('P-256 private scalar out of range');
    }
    final pt = P256Curve._scalarMul(d, P256Curve.gx, P256Curve.gy);
    if (pt == null || !P256Curve.isOnCurve(pt.x, pt.y)) {
      throw StateError('invalid P-256 key pair');
    }
    return P256KeyPair._(d, PublicEcJwk.fromPoint(pt.x, pt.y, kid: kid));
  }

  Uint8List ecdhSharedSecret(PublicEcJwk peerPublicKey) =>
      P256Curve.ecdhSharedSecret(_d, peerPublicKey);

  Uint8List signEs256(List<int> message, {Random? random}) {
    final rng = random ?? Random.secure();
    final e = _bytesToBigInt(sha256Bytes(message));
    while (true) {
      final k = P256Curve._randomScalar(rng);
      final pt = P256Curve._scalarMul(k, P256Curve.gx, P256Curve.gy);
      if (pt == null) continue;
      final r = P256Curve._modN(pt.x);
      if (r == BigInt.zero) continue;
      final kInv = k.modInverse(P256Curve.n);
      var s = P256Curve._modN(kInv * (e + r * _d));
      if (s == BigInt.zero) continue;
      if (s > P256Curve.halfN) {
        s = P256Curve.n - s;
      }
      final out = Uint8List(64);
      out.setRange(0, 32, _bigIntTo32Bytes(r));
      out.setRange(32, 64, _bigIntTo32Bytes(s));
      return out;
    }
  }
}

typedef Es256Signer = Future<Uint8List> Function(Uint8List signingInput);

/// Builds a compact JWS (`openid4vci-proof+jwt`) bound to [audience] and [nonce].
Future<String> buildHolderProofJwt({
  required PublicEcJwk publicJwk,
  required Es256Signer signEs256,
  required String audience,
  required String nonce,
  DateTime? issuedAt,
}) async {
  if (audience.isEmpty || nonce.isEmpty) {
    throw ArgumentError('audience and nonce must not be empty');
  }
  final header = <String, dynamic>{
    'alg': 'ES256',
    'typ': oid4vciProofJwtType,
    'jwk': publicJwk.toProofHeaderJwk(),
  };
  final payload = <String, dynamic>{
    'aud': audience,
    'nonce': nonce,
    'iat': (issuedAt ?? DateTime.now()).toUtc().millisecondsSinceEpoch ~/ 1000,
  };
  final headerB64 = base64UrlNoPadEncode(utf8.encode(jsonEncode(header)));
  final payloadB64 = base64UrlNoPadEncode(utf8.encode(jsonEncode(payload)));
  final signingInput = '$headerB64.$payloadB64';
  final sig64 = await signEs256(Uint8List.fromList(utf8.encode(signingInput)));
  if (sig64.length != 64) {
    throw StateError('expected 64-byte raw ES256 signature');
  }
  return '$signingInput.${base64UrlNoPadEncode(sig64)}';
}

/// Builds a compact VCDM 2.0 `vp+jwt` presentation wrapping [credentials]
/// as `EnvelopedVerifiableCredential` data URLs, bound to [audience] and [nonce].
Future<String> buildVerifiablePresentationJwt({
  required PublicEcJwk holderPublicJwk,
  required Es256Signer signEs256,
  required String audience,
  required String nonce,
  required List<String> credentials,
}) async {
  if (audience.isEmpty || nonce.isEmpty) {
    throw ArgumentError('audience and nonce must not be empty');
  }
  if (credentials.isEmpty) {
    throw ArgumentError('credentials must not be empty');
  }
  final enveloped = <Map<String, dynamic>>[
    for (final vc in credentials)
      if (vc.trim().isEmpty)
        throw ArgumentError('credential JWT must not be empty')
      else
        <String, dynamic>{
          '@context': vcdmBaseContext,
          'id': 'data:application/vc+jwt,${vc.trim()}',
          'type': 'EnvelopedVerifiableCredential',
        },
  ];
  final header = <String, dynamic>{
    'alg': 'ES256',
    'typ': oid4vpPresentationJwtType,
    'jwk': holderPublicJwk.toProofHeaderJwk(),
  };
  final payload = <String, dynamic>{
    '@context': <String>[vcdmBaseContext, hukidPresentationContext],
    'type': <String>['VerifiablePresentation'],
    'aud': audience,
    'nonce': nonce,
    'verifiableCredential': enveloped,
  };
  final headerB64 = base64UrlNoPadEncode(utf8.encode(jsonEncode(header)));
  final payloadB64 = base64UrlNoPadEncode(utf8.encode(jsonEncode(payload)));
  final signingInput = '$headerB64.$payloadB64';
  final sig64 = await signEs256(Uint8List.fromList(utf8.encode(signingInput)));
  if (sig64.length != 64) {
    throw StateError('expected 64-byte raw ES256 signature');
  }
  return '$signingInput.${base64UrlNoPadEncode(sig64)}';
}
