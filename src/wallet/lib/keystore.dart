import 'dart:convert';

import 'package:flutter/services.dart';

import 'crypto_p256.dart';

/// Port for generating and using non-exportable holder ES256 keys.
abstract interface class HolderKeyStore {
  Future<PublicEcJwk> ensureKey(String alias);
  Future<Uint8List> signEs256(String alias, Uint8List data);
  Future<void> deleteKey(String alias);
}

/// Android Keystore-backed holder key store via platform channel.
class AndroidKeystoreHolderKeyStore implements HolderKeyStore {
  AndroidKeystoreHolderKeyStore({MethodChannel? channel})
    : _channel =
          channel ?? const MethodChannel('dev.example.hukid_wallet/keystore');

  final MethodChannel _channel;

  @override
  Future<PublicEcJwk> ensureKey(String alias) async {
    final raw = await _channel.invokeMapMethod<String, dynamic>(
      'ensureHolderKey',
      <String, dynamic>{'alias': alias},
    );
    if (raw == null) {
      throw StateError('Android Keystore returned null key');
    }
    return PublicEcJwk.fromJson(raw);
  }

  @override
  Future<Uint8List> signEs256(String alias, Uint8List data) async {
    final sig = await _channel.invokeMethod<Uint8List>(
      'signEs256',
      <String, dynamic>{'alias': alias, 'data': data},
    );
    if (sig == null || sig.length != 64) {
      throw StateError('Android Keystore returned invalid ES256 signature');
    }
    return sig;
  }

  @override
  Future<void> deleteKey(String alias) async {
    await _channel.invokeMethod<void>(
      'deleteHolderKey',
      <String, dynamic>{'alias': alias},
    );
  }
}

/// Software P-256 holder key store for unit/HTTP integration tests.
class MemoryHolderKeyStore implements HolderKeyStore {
  final Map<String, P256KeyPair> _keys = <String, P256KeyPair>{};

  @override
  Future<PublicEcJwk> ensureKey(String alias) async {
    final pair = _keys.putIfAbsent(alias, () => P256KeyPair.generate());
    return pair.publicJwk;
  }

  @override
  Future<Uint8List> signEs256(String alias, Uint8List data) async {
    final pair = _keys[alias];
    if (pair == null) {
      throw StateError('holder key $alias not initialized');
    }
    return pair.signEs256(data);
  }

  @override
  Future<void> deleteKey(String alias) async {
    _keys.remove(alias);
  }
}

/// Encrypted credential record stored in the wallet vault.
class StoredCredential {
  const StoredCredential({
    required this.id,
    required this.credentialIssuer,
    required this.configurationId,
    required this.title,
    required this.issuerDisplayName,
    required this.holderJkt,
    required this.keyAlias,
    required this.vcJwt,
    required this.receivedAtIso,
  });

  final String id;
  final String credentialIssuer;
  final String configurationId;
  final String title;
  final String issuerDisplayName;
  final String holderJkt;
  final String keyAlias;
  final String vcJwt;
  final String receivedAtIso;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'kind': 'credential',
    'id': id,
    'credentialIssuer': credentialIssuer,
    'configurationId': configurationId,
    'title': title,
    'issuerDisplayName': issuerDisplayName,
    'holderJkt': holderJkt,
    'keyAlias': keyAlias,
    'vcJwt': vcJwt,
    'receivedAtIso': receivedAtIso,
  };

  factory StoredCredential.fromJson(Map<String, dynamic> json) {
    final id = json['id'];
    final credentialIssuer = json['credentialIssuer'];
    final configurationId = json['configurationId'];
    final title = json['title'];
    final issuerDisplayName = json['issuerDisplayName'];
    final holderJkt = json['holderJkt'];
    final keyAlias = json['keyAlias'];
    final vcJwt = json['vcJwt'];
    final receivedAtIso = json['receivedAtIso'];
    if (id is! String ||
        credentialIssuer is! String ||
        configurationId is! String ||
        title is! String ||
        issuerDisplayName is! String ||
        holderJkt is! String ||
        keyAlias is! String ||
        vcJwt is! String ||
        receivedAtIso is! String) {
      throw const FormatException('invalid StoredCredential record');
    }
    return StoredCredential(
      id: id,
      credentialIssuer: credentialIssuer,
      configurationId: configurationId,
      title: title,
      issuerDisplayName: issuerDisplayName,
      holderJkt: holderJkt,
      keyAlias: keyAlias,
      vcJwt: vcJwt,
      receivedAtIso: receivedAtIso,
    );
  }
}

/// Pending OID4VCI deferred issuance transaction persisted while waiting for signing.
class PendingDeferredIssuance {
  const PendingDeferredIssuance({
    required this.id,
    required this.credentialIssuer,
    required this.deferredEndpoint,
    required this.accessToken,
    required this.transactionId,
    required this.intervalSeconds,
    required this.configurationId,
    required this.title,
    required this.issuerDisplayName,
    required this.holderJkt,
    required this.keyAlias,
    required this.createdAtIso,
  });

  final String id;
  final String credentialIssuer;
  final String deferredEndpoint;
  final String accessToken;
  final String transactionId;
  final int intervalSeconds;
  final String configurationId;
  final String title;
  final String issuerDisplayName;
  final String holderJkt;
  final String keyAlias;
  final String createdAtIso;

  Map<String, dynamic> toJson() => <String, dynamic>{
    'kind': 'pending',
    'id': id,
    'credentialIssuer': credentialIssuer,
    'deferredEndpoint': deferredEndpoint,
    'accessToken': accessToken,
    'transactionId': transactionId,
    'intervalSeconds': intervalSeconds,
    'configurationId': configurationId,
    'title': title,
    'issuerDisplayName': issuerDisplayName,
    'holderJkt': holderJkt,
    'keyAlias': keyAlias,
    'createdAtIso': createdAtIso,
  };

  factory PendingDeferredIssuance.fromJson(Map<String, dynamic> json) {
    final id = json['id'];
    final credentialIssuer = json['credentialIssuer'];
    final deferredEndpoint = json['deferredEndpoint'];
    final accessToken = json['accessToken'];
    final transactionId = json['transactionId'];
    final intervalSeconds = json['intervalSeconds'];
    final configurationId = json['configurationId'];
    final title = json['title'];
    final issuerDisplayName = json['issuerDisplayName'];
    final holderJkt = json['holderJkt'];
    final keyAlias = json['keyAlias'];
    final createdAtIso = json['createdAtIso'];
    if (id is! String ||
        credentialIssuer is! String ||
        deferredEndpoint is! String ||
        accessToken is! String ||
        transactionId is! String ||
        intervalSeconds is! int ||
        configurationId is! String ||
        title is! String ||
        issuerDisplayName is! String ||
        holderJkt is! String ||
        keyAlias is! String ||
        createdAtIso is! String) {
      throw const FormatException('invalid PendingDeferredIssuance record');
    }
    return PendingDeferredIssuance(
      id: id,
      credentialIssuer: credentialIssuer,
      deferredEndpoint: deferredEndpoint,
      accessToken: accessToken,
      transactionId: transactionId,
      intervalSeconds: intervalSeconds,
      configurationId: configurationId,
      title: title,
      issuerDisplayName: issuerDisplayName,
      holderJkt: holderJkt,
      keyAlias: keyAlias,
      createdAtIso: createdAtIso,
    );
  }
}

/// Encrypted vault interface storing received credentials and pending deferred tokens.
abstract interface class CredentialVault {
  Future<void> saveCredential(StoredCredential credential);
  Future<List<StoredCredential>> listCredentials();
  Future<void> deleteCredential(String id);
  Future<void> savePendingDeferred(PendingDeferredIssuance pending);
  Future<List<PendingDeferredIssuance>> listPendingDeferred();
  Future<void> deletePendingDeferred(String id);
}

/// Derives a filename-safe storage identifier from arbitrary inputs.
String safeVaultId(String prefix, String rawKey) {
  final digest = sha256Bytes(utf8.encode('$prefix|$rawKey'));
  final tag = base64UrlNoPadEncode(digest).substring(0, 22);
  return '${prefix}_$tag';
}

/// AES-256-GCM encrypted credential vault backed by AndroidKeyStore.
class AndroidEncryptedVault implements CredentialVault {
  AndroidEncryptedVault({MethodChannel? channel})
    : _channel = channel ?? const MethodChannel('dev.example.hukid_wallet/vault');

  final MethodChannel _channel;

  @override
  Future<void> saveCredential(StoredCredential credential) async {
    await _channel.invokeMethod<void>('saveRecord', <String, dynamic>{
      'id': credential.id,
      'plaintext': jsonEncode(credential.toJson()),
    });
  }

  @override
  Future<void> deleteCredential(String id) async {
    await _channel.invokeMethod<void>('deleteRecord', <String, dynamic>{
      'id': id,
    });
  }

  @override
  Future<void> savePendingDeferred(PendingDeferredIssuance pending) async {
    await _channel.invokeMethod<void>('saveRecord', <String, dynamic>{
      'id': pending.id,
      'plaintext': jsonEncode(pending.toJson()),
    });
  }

  @override
  Future<void> deletePendingDeferred(String id) async {
    await _channel.invokeMethod<void>('deleteRecord', <String, dynamic>{
      'id': id,
    });
  }

  @override
  Future<List<StoredCredential>> listCredentials() async {
    final rows = await _readAllDecoded();
    final out = <StoredCredential>[];
    for (final row in rows) {
      if (row['kind'] == 'credential') {
        out.add(StoredCredential.fromJson(row));
      }
    }
    return out;
  }

  @override
  Future<List<PendingDeferredIssuance>> listPendingDeferred() async {
    final rows = await _readAllDecoded();
    final out = <PendingDeferredIssuance>[];
    for (final row in rows) {
      if (row['kind'] == 'pending') {
        out.add(PendingDeferredIssuance.fromJson(row));
      }
    }
    return out;
  }

  Future<List<Map<String, dynamic>>> _readAllDecoded() async {
    final raw = await _channel.invokeListMethod<String>('readAllRecords');
    if (raw == null) return <Map<String, dynamic>>[];
    final out = <Map<String, dynamic>>[];
    for (final entry in raw) {
      final decoded = jsonDecode(entry);
      if (decoded is Map<String, dynamic>) {
        out.add(decoded);
      }
    }
    return out;
  }
}

/// Ephemeral in-memory vault for tests and fallback runs.
class MemoryCredentialVault implements CredentialVault {
  final Map<String, StoredCredential> _credentials =
      <String, StoredCredential>{};
  final Map<String, PendingDeferredIssuance> _pending =
      <String, PendingDeferredIssuance>{};

  @override
  Future<void> saveCredential(StoredCredential credential) async {
    _credentials[credential.id] = credential;
  }

  @override
  Future<List<StoredCredential>> listCredentials() async =>
      _credentials.values.toList(growable: false);

  @override
  Future<void> deleteCredential(String id) async {
    _credentials.remove(id);
  }

  @override
  Future<void> savePendingDeferred(PendingDeferredIssuance pending) async {
    _pending[pending.id] = pending;
  }

  @override
  Future<List<PendingDeferredIssuance>> listPendingDeferred() async =>
      _pending.values.toList(growable: false);

  @override
  Future<void> deletePendingDeferred(String id) async {
    _pending.remove(id);
  }
}
