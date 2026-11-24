import 'dart:async';

import 'keystore.dart';

enum ReceiptState { idle, loading, preview, pending, stored, unavailable }

class OfferPreview {
  const OfferPreview({
    required this.issuer,
    required this.title,
    this.configurationId = '',
    this.credentialIssuer = '',
    this.previewId = '',
  });

  final String issuer;
  final String title;
  final String configurationId;
  final String credentialIssuer;
  final String previewId;
}

class ReceiveOutcome {
  const ReceiveOutcome._({
    required this.state,
    this.credential,
    this.deferred,
  });

  const ReceiveOutcome.unavailable()
    : this._(state: ReceiptState.unavailable);

  const ReceiveOutcome.pending(PendingDeferredIssuance? deferred)
    : this._(state: ReceiptState.pending, deferred: deferred);

  const ReceiveOutcome.stored(StoredCredential? credential)
    : this._(state: ReceiptState.stored, credential: credential);

  final ReceiptState state;
  final StoredCredential? credential;
  final PendingDeferredIssuance? deferred;
}

// Implementations must obtain previews from configured trust or verified OID4VCI metadata,
// never from raw URL text alone.
abstract interface class OfferAdapter {
  FutureOr<OfferPreview?> preview(String link);
  Future<ReceiveOutcome> request(OfferPreview offer);
  Future<ReceiveOutcome> pollDeferred(PendingDeferredIssuance pending);
}

class UnavailableIssuer implements OfferAdapter {
  const UnavailableIssuer();

  @override
  OfferPreview? preview(String link) => null;

  @override
  Future<ReceiveOutcome> request(OfferPreview offer) async =>
      const ReceiveOutcome.unavailable();

  @override
  Future<ReceiveOutcome> pollDeferred(PendingDeferredIssuance pending) async =>
      const ReceiveOutcome.unavailable();
}

class Issuance {
  Issuance(this._adapter);

  final OfferAdapter _adapter;
  OfferPreview? _offer;
  StoredCredential? _credential;
  PendingDeferredIssuance? _deferred;
  ReceiptState _state = ReceiptState.idle;
  int _generation = 0;

  OfferPreview? get offer => _offer;
  StoredCredential? get credential => _credential;
  PendingDeferredIssuance? get deferred => _deferred;
  ReceiptState get state => _state;

  Future<void> preview(String link) async {
    if (_state == ReceiptState.pending || _state == ReceiptState.loading) {
      return;
    }
    cancel();
    final generation = _generation;
    OfferPreview? resolved;
    try {
      final result = _adapter.preview(link.trim());
      if (result is Future<OfferPreview?>) {
        _state = ReceiptState.loading;
        resolved = await result;
      } else {
        resolved = result;
      }
    } catch (_) {
      resolved = null;
    }
    if (_generation != generation) return;
    _offer = resolved;
    _state = resolved == null ? ReceiptState.unavailable : ReceiptState.preview;
  }

  void cancel() {
    _generation++;
    _offer = null;
    _credential = null;
    _deferred = null;
    _state = ReceiptState.idle;
  }

  Future<void> receive({required bool consent}) async {
    if (!consent || _state != ReceiptState.preview || _offer == null) return;
    final generation = _generation;
    _state = ReceiptState.pending;
    var nextState = ReceiptState.unavailable;
    StoredCredential? nextCred;
    PendingDeferredIssuance? nextDeferred;
    try {
      final outcome = await _adapter.request(_offer!);
      if (outcome.state == ReceiptState.stored) {
        nextState = ReceiptState.stored;
        nextCred = outcome.credential;
      } else if (outcome.state == ReceiptState.pending) {
        nextState = ReceiptState.pending;
        nextDeferred = outcome.deferred;
      }
    } catch (_) {
      // Never expose raw adapter errors or sensitive offer codes.
    }
    if (_generation == generation) {
      _state = nextState;
      _credential = nextCred;
      _deferred = nextDeferred;
    }
  }

  Future<void> pollPending() async {
    final pending = _deferred;
    if (pending == null || _state != ReceiptState.pending) return;
    final generation = _generation;
    var nextState = ReceiptState.unavailable;
    StoredCredential? nextCred;
    PendingDeferredIssuance? nextDeferred;
    try {
      final outcome = await _adapter.pollDeferred(pending);
      if (outcome.state == ReceiptState.stored) {
        nextState = ReceiptState.stored;
        nextCred = outcome.credential;
      } else if (outcome.state == ReceiptState.pending) {
        nextState = ReceiptState.pending;
        nextDeferred = outcome.deferred ?? pending;
      }
    } catch (_) {
      nextState = ReceiptState.unavailable;
    }
    if (_generation == generation) {
      _state = nextState;
      _credential = nextCred;
      _deferred = nextDeferred;
    }
  }
}
