import 'dart:async';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import 'checkin_pass.dart';
import 'credential_card.dart';
import 'issuance.dart';
import 'keystore.dart';
import 'lab_verifier.dart';
import 'oid4vci_client.dart';
import 'oid4vp_client.dart';
import 'qr_scanner.dart';

const bool _allowInsecureLoopback = bool.fromEnvironment(
  'HUKID_ALLOW_INSECURE_LOOPBACK',
);

void main() => runApp(WalletApp.live());

class WalletApp extends StatelessWidget {
  const WalletApp({
    super.key,
    this.adapter = const UnavailableIssuer(),
    this.presentationAdapter = const UnavailableVerifier(),
    this.vault,
    this.enableDeepLinks = false,
    this.scanner,
    this.passIssuer,
  });

  factory WalletApp.live({
    Key? key,
    Oid4vciHttpClient? httpClient,
    Oid4vciConfig config = const Oid4vciConfig(
      allowInsecureLoopback: _allowInsecureLoopback,
    ),
  }) {
    final vault = AndroidEncryptedVault();
    final keyStore = AndroidKeystoreHolderKeyStore();
    final adapter = Oid4vciOfferAdapter(
      keyStore: keyStore,
      vault: vault,
      httpClient: httpClient,
      config: config,
    );
    final lab = labVerifierFromEnvironment(
      labEnabled: config.allowInsecureLoopback,
    );
    final presentationAdapter = Oid4vpPresentationAdapter(
      keyStore: keyStore,
      httpClient: lab == null
          ? httpClient
          : IoOid4vciHttpClient(client: lab.httpClient()),
      config: config,
      verifierSigningKeys: lab?.signingKeys,
      allowedVerifierOrigins: lab == null ? null : {lab.origin},
    );
    return WalletApp(
      key: key,
      adapter: adapter,
      presentationAdapter: presentationAdapter,
      vault: vault,
      enableDeepLinks: true,
      scanner: const AndroidQrScanner(),
      passIssuer: HukidPassClient(
        keyStore: keyStore,
        httpClient: httpClient,
        config: config,
      ),
    );
  }

  final OfferAdapter adapter;
  final PresentationAdapter presentationAdapter;
  final CredentialVault? vault;
  final bool enableDeepLinks;

  /// Con escáner, las pantallas sólo leen QR. Sin él (laboratorio y pruebas)
  /// conservan el campo de enlace.
  final QrScanner? scanner;
  final PassIssuer? passIssuer;

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'HukID Wallet',
    debugShowCheckedModeBanner: false,
    theme: ThemeData(
      colorScheme: ColorScheme.fromSeed(
        seedColor: const Color(0xff5027bc),
        primary: const Color(0xff5027bc),
        surface: Colors.white,
        onSurface: const Color(0xff24173d),
      ),
      scaffoldBackgroundColor: Colors.white,
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          minimumSize: const Size(48, 48),
          padding: const EdgeInsets.all(16),
        ),
      ),
    ),
    home: WalletHome(
      adapter: adapter,
      presentationAdapter: presentationAdapter,
      vault: vault,
      enableDeepLinks: enableDeepLinks,
      scanner: scanner,
      passIssuer: passIssuer,
    ),
  );
}

class WalletHome extends StatefulWidget {
  const WalletHome({
    super.key,
    this.adapter = const UnavailableIssuer(),
    this.presentationAdapter = const UnavailableVerifier(),
    this.vault,
    this.enableDeepLinks = false,
    this.scanner,
    this.passIssuer,
  });

  final OfferAdapter adapter;
  final PresentationAdapter presentationAdapter;
  final CredentialVault? vault;
  final bool enableDeepLinks;
  final QrScanner? scanner;
  final PassIssuer? passIssuer;

  @override
  State<WalletHome> createState() => _WalletHomeState();
}

class _WalletHomeState extends State<WalletHome> {
  static const _deepLinkChannel = MethodChannel(
    'dev.example.hukid_wallet/deeplink',
  );

  List<StoredCredential> _credentials = const <StoredCredential>[];
  List<PendingDeferredIssuance> _pending = const <PendingDeferredIssuance>[];
  String? _statusNote;

  @override
  void initState() {
    super.initState();
    if (widget.enableDeepLinks) {
      _deepLinkChannel.setMethodCallHandler(_handleDeepLinkCall);
    }
    unawaited(_bootstrap());
  }

  Future<void> _bootstrap() async {
    await _reloadVault();
    if (widget.enableDeepLinks && mounted) {
      await _consumeInitialDeepLink();
    }
  }

  @override
  void dispose() {
    if (widget.enableDeepLinks) {
      _deepLinkChannel.setMethodCallHandler(null);
    }
    super.dispose();
  }

  Future<void> _handleDeepLinkCall(MethodCall call) async {
    if (call.method == 'onLink' && call.arguments is String) {
      await _openDeepLink(call.arguments as String);
    }
  }

  Future<void> _consumeInitialDeepLink() async {
    try {
      final link = await _deepLinkChannel.invokeMethod<String>(
        'consumeInitialLink',
      );
      if (link != null && link.isNotEmpty && mounted) {
        await _openDeepLink(link);
      }
    } catch (_) {
      // Ignora canal no disponible en plataformas sin soporte nativo.
    }
  }

  Future<void> _openDeepLink(String rawLink) async {
    final trimmed = rawLink.trim();
    if (trimmed.startsWith(oid4vpScheme)) {
      await _openPresentPage(initialLink: trimmed);
    } else {
      await _openReceivePage(initialLink: trimmed);
    }
  }

  Future<void> _reloadVault() async {
    final vault = widget.vault;
    if (vault == null) return;
    try {
      final creds = await vault.listCredentials();
      final pending = await vault.listPendingDeferred();
      if (!mounted) return;
      setState(() {
        _credentials = creds;
        _pending = pending;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _statusNote = 'No se pudo leer el almacén cifrado local.';
      });
    }
  }

  Future<void> _openReceivePage({String? initialLink}) async {
    await Navigator.of(context).push<void>(
      MaterialPageRoute<void>(
        builder: (_) => ReceivePage(
          adapter: widget.adapter,
          initialLink: initialLink,
          scanner: widget.scanner,
        ),
      ),
    );
    await _reloadVault();
  }

  Future<void> _openPresentPage({String? initialLink}) async {
    await _reloadVault();
    if (!mounted) return;
    await Navigator.of(context).push<void>(
      MaterialPageRoute<void>(
        builder: (_) => PresentPage(
          adapter: widget.presentationAdapter,
          credentials: _credentials,
          initialLink: initialLink,
          scanner: widget.scanner,
        ),
      ),
    );
  }

  Future<void> _pollPendingItem(PendingDeferredIssuance item) async {
    setState(() {
      _statusNote = 'Consultando emisión diferida…';
    });
    final outcome = await widget.adapter.pollDeferred(item);
    await _reloadVault();
    if (!mounted) return;
    setState(() {
      if (outcome.state == ReceiptState.stored) {
        _statusNote = 'Credencial emitida y guardada cifrada.';
      } else if (outcome.state == ReceiptState.pending) {
        _statusNote =
            'El emisor aún procesa la firma (${item.configurationId}).';
      } else {
        _statusNote = 'No se pudo recuperar la emisión diferida.';
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final isLab = widget.adapter is UnavailableIssuer;
    final count = _credentials.length;
    final countLabel = count == 1 ? '1 credencial' : '$count credenciales';

    return Scaffold(
      appBar: AppBar(title: const Text('hukid.')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Text('Mi wallet', style: Theme.of(context).textTheme.headlineLarge),
            const Text('Tus credenciales. Tú decides.'),
            const SizedBox(height: 24),
            Text(countLabel),
            if (_credentials.isEmpty)
              const Card(
                color: Color(0xfff3effb),
                child: Padding(
                  padding: EdgeInsets.all(24),
                  child: Column(
                    children: [
                      Icon(Icons.wallet_outlined, size: 48),
                      SizedBox(height: 16),
                      Text('Este espacio es tuyo.'),
                      Text('Todavía no hay credenciales en tu wallet.'),
                    ],
                  ),
                ),
              )
            else
              ..._credentials.map(
                (cred) => CredentialCard(
                  credential: cred,
                  onTap: () => unawaited(
                    Navigator.of(context).push<void>(
                      MaterialPageRoute<void>(
                        builder: (detail) => CredentialDetailPage(
                          credential: cred,
                          onShowPass:
                              widget.passIssuer != null &&
                                  supportsCheckinPass(cred)
                              ? () => unawaited(
                                  Navigator.of(detail).push<void>(
                                    MaterialPageRoute<void>(
                                      builder: (_) => PassPage(
                                        issuer: widget.passIssuer!,
                                        credential: cred,
                                      ),
                                    ),
                                  ),
                                )
                              : null,
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            if (_pending.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text(
                'Emisiones diferidas pendientes',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              ..._pending.map(
                (item) => Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(item.title),
                        Text('Emisor: ${item.issuerDisplayName}'),
                        const SizedBox(height: 8),
                        FilledButton(
                          onPressed: () => unawaited(_pollPendingItem(item)),
                          child: const Text('Consultar estado'),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ],
            if (_statusNote != null) ...[
              const SizedBox(height: 12),
              Text(_statusNote!),
            ],
            const SizedBox(height: 16),
            FilledButton.icon(
              icon: const Icon(Icons.add),
              label: const Text('Recibir credencial'),
              onPressed: () => unawaited(_openReceivePage()),
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              icon: const Icon(Icons.verified_user_outlined),
              label: const Text('Presentar credencial'),
              onPressed: () => unawaited(_openPresentPage()),
            ),
            const SizedBox(height: 16),
            Text(
              isLab
                  ? 'Laboratorio Android · Sin emisor configurado.'
                  : 'HukID Wallet · OID4VCI + OID4VP + Android Keystore.',
            ),
            if (isLab)
              const Text(
                'Sin cámara, recepción real ni almacenamiento todavía.',
              ),
          ],
        ),
      ),
    );
  }
}

class ReceivePage extends StatefulWidget {
  const ReceivePage({
    super.key,
    required this.adapter,
    this.initialLink,
    this.scanner,
  });

  final OfferAdapter adapter;
  final String? initialLink;
  final QrScanner? scanner;

  @override
  State<ReceivePage> createState() => _ReceivePageState();
}

class _ReceivePageState extends State<ReceivePage> {
  late final flow = Issuance(widget.adapter);
  final input = TextEditingController();
  bool consent = false;
  bool scanning = false;
  String? scanNote;
  Timer? _deferredPollTimer;

  Future<void> _scanOffer() async {
    setState(() {
      scanning = true;
      scanNote = null;
    });
    String? text;
    try {
      text = (await widget.scanner!.scan())?.trim();
    } catch (_) {
      scanNote = qrScannerFailureMessage;
    }
    if (!mounted) return;
    setState(() => scanning = false);
    if (text == null) return;
    if (!text.startsWith('openid-credential-offer://')) {
      setState(() {
        scanNote = text!.startsWith(oid4vpScheme)
            ? 'Ese QR es para presentar una credencial. Usa «Presentar credencial».'
            : 'Ese QR no es una oferta de credencial.';
      });
      return;
    }
    input.text = text;
    await _inspectOffer();
  }

  @override
  void initState() {
    super.initState();
    final initial = widget.initialLink;
    if (initial != null && initial.trim().isNotEmpty) {
      input.text = initial.trim();
      unawaited(_inspectOffer());
    }
  }

  @override
  void dispose() {
    _deferredPollTimer?.cancel();
    flow.cancel();
    input.dispose();
    super.dispose();
  }

  Future<void> _inspectOffer() async {
    consent = false;
    final task = flow.preview(input.text);
    if (mounted) setState(() {});
    await task;
    if (mounted) setState(() {});
  }

  Future<void> receive() async {
    final result = flow.receive(consent: consent);
    setState(() {});
    await result;
    if (mounted) {
      setState(() {});
      _scheduleDeferredPoll();
    }
  }

  Future<void> pollDeferred() async {
    _deferredPollTimer?.cancel();
    final result = flow.pollPending();
    setState(() {});
    await result;
    if (mounted) {
      setState(() {});
      _scheduleDeferredPoll();
    }
  }

  void _scheduleDeferredPoll() {
    _deferredPollTimer?.cancel();
    final pending = flow.deferred;
    if (!mounted || flow.state != ReceiptState.pending || pending == null) {
      return;
    }
    final seconds = pending.intervalSeconds.clamp(1, 30);
    _deferredPollTimer = Timer(
      Duration(seconds: seconds),
      () => unawaited(pollDeferred()),
    );
  }

  @override
  Widget build(BuildContext context) {
    final offer = flow.offer;
    final reviewing = flow.state == ReceiptState.preview;
    final loading = flow.state == ReceiptState.loading;

    return Scaffold(
      appBar: AppBar(title: const Text('Recibir credencial')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            if (offer == null && widget.scanner != null) ...[
              const Text(
                'Escanea el código QR que te muestra tu organización para recibir tu credencial.',
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                icon: const Icon(Icons.qr_code_scanner),
                onPressed: loading || scanning
                    ? null
                    : () => unawaited(_scanOffer()),
                label: Text(loading ? 'Consultando…' : 'Escanear QR'),
              ),
              if (scanNote != null) ...[
                const SizedBox(height: 12),
                Semantics(liveRegion: true, child: Text(scanNote!)),
              ],
            ] else if (offer == null) ...[
              const Text('Usar enlace'),
              Text(
                widget.adapter is UnavailableIssuer
                    ? 'No pegues datos personales ni códigos reales. '
                          'No se abrirán enlaces externos.'
                    : 'Pega el enlace openid-credential-offer:// emitido por tu organización.',
              ),
              const SizedBox(height: 16),
              TextField(
                controller: input,
                autocorrect: false,
                enableSuggestions: false,
                decoration: const InputDecoration(
                  labelText: 'Enlace de oferta',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: loading ? null : () => unawaited(_inspectOffer()),
                child: Text(loading ? 'Consultando…' : 'Revisar oferta'),
              ),
            ] else ...[
              Text(
                'Una credencial para ti',
                style: Theme.of(context).textTheme.headlineMedium,
              ),
              const SizedBox(height: 16),
              Text(offer.issuer),
              Text(offer.title),
              const Text(
                'Vista previa. No acredita firma, estado ni validez. '
                'Revisa qué recibirás antes de solicitarlo.',
              ),
              CheckboxListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text(
                  'Consiento solicitar esta credencial al emisor.',
                ),
                value: consent,
                onChanged: reviewing
                    ? (value) => setState(() => consent = value == true)
                    : null,
              ),
              FilledButton(
                onPressed: reviewing && consent ? receive : null,
                child: const Text('Solicitar recepción'),
              ),
            ],
            if (flow.state == ReceiptState.pending) ...[
              const SizedBox(height: 12),
              Semantics(
                liveRegion: true,
                child: const Text('Recepción pendiente'),
              ),
              if (flow.deferred != null) ...[
                const SizedBox(height: 8),
                const Text(
                  'HukID está firmando la credencial. La recepción se actualizará automáticamente.',
                ),
              ],
            ],
            if (flow.state == ReceiptState.stored) ...[
              const SizedBox(height: 12),
              Semantics(
                liveRegion: true,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Credencial guardada'),
                    if (flow.credential != null)
                      Text('Almacenada cifrada (${flow.credential!.title}).'),
                  ],
                ),
              ),
            ],
            if (flow.state == ReceiptState.unavailable)
              Semantics(
                liveRegion: true,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Recepción no disponible'),
                    if (offer == null)
                      Text(
                        widget.adapter is UnavailableIssuer
                            ? 'Sin emisor configurado. Integración no disponible.'
                            : 'No se pudo verificar o completar la oferta.',
                      ),
                    const Text('No se guardó ninguna credencial.'),
                  ],
                ),
              ),
            const SizedBox(height: 16),
            TextButton(
              onPressed: () {
                flow.cancel();
                Navigator.of(context).pop();
              },
              child: Text(
                flow.state == ReceiptState.stored ? 'Volver' : 'Cancelar',
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class PresentPage extends StatefulWidget {
  const PresentPage({
    super.key,
    required this.adapter,
    required this.credentials,
    this.initialLink,
    this.scanner,
  });

  final PresentationAdapter adapter;
  final List<StoredCredential> credentials;
  final String? initialLink;
  final QrScanner? scanner;

  @override
  State<PresentPage> createState() => _PresentPageState();
}

class _PresentPageState extends State<PresentPage> {
  final TextEditingController _input = TextEditingController();
  PresentationRequestSummary? _request;
  String? _selectedCredentialId;
  bool _busy = false;
  bool _submitted = false;
  String? _statusNote;
  bool _scanning = false;

  Future<void> _scanRequest() async {
    setState(() {
      _scanning = true;
      _statusNote = null;
    });
    String? text;
    String? failure;
    try {
      text = (await widget.scanner!.scan())?.trim();
    } catch (_) {
      failure = qrScannerFailureMessage;
    }
    if (!mounted) return;
    setState(() {
      _scanning = false;
      _statusNote = failure;
    });
    if (text == null) return;
    if (!text.startsWith(oid4vpScheme)) {
      setState(() {
        _statusNote = text!.startsWith('openid-credential-offer://')
            ? 'Ese QR es para recibir una credencial. Usa «Recibir credencial».'
            : 'Ese QR no es una solicitud de verificación.';
      });
      return;
    }
    _input.text = text;
    await _fetchRequest();
  }

  @override
  void initState() {
    super.initState();
    if (widget.credentials.isNotEmpty) {
      _selectedCredentialId = widget.credentials.first.id;
    }
    final initial = widget.initialLink?.trim();
    if (initial != null && initial.isNotEmpty) {
      _input.text = initial;
      unawaited(_fetchRequest());
    }
  }

  @override
  void dispose() {
    _input.dispose();
    super.dispose();
  }

  StoredCredential? get _selectedCredential {
    for (final cred in widget.credentials) {
      if (cred.id == _selectedCredentialId) return cred;
    }
    return null;
  }

  Future<void> _fetchRequest() async {
    setState(() {
      _busy = true;
      _request = null;
      _submitted = false;
      _statusNote = null;
    });
    try {
      final summary = await widget.adapter.fetchRequest(_input.text);
      if (!mounted) return;
      setState(() {
        _request = summary;
        _busy = false;
      });
    } catch (err) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _statusNote = err.toString();
      });
    }
  }

  Future<void> _submitPresentation() async {
    final req = _request;
    final cred = _selectedCredential;
    if (req == null || cred == null) return;
    setState(() {
      _busy = true;
      _statusNote = null;
    });
    try {
      final outcome = await widget.adapter.presentCredential(
        request: req,
        credential: cred,
      );
      if (!mounted) return;
      setState(() {
        _busy = false;
        _submitted = outcome.state == PresentationState.submitted;
        _statusNote = outcome.state == PresentationState.submitted
            ? 'Presentación enviada al validador.'
            : (outcome.detail ?? 'El validador rechazó la presentación.');
      });
    } catch (err) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _statusNote = err.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final req = _request;
    return Scaffold(
      appBar: AppBar(title: const Text('Presentar credencial')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            if (widget.scanner != null) ...[
              const Text(
                'Escanea el código QR del validador. Verás la solicitud antes de enviar nada.',
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                icon: const Icon(Icons.qr_code_scanner),
                onPressed: _busy || _scanning
                    ? null
                    : () => unawaited(_scanRequest()),
                label: Text(
                  _busy && req == null ? 'Consultando…' : 'Escanear QR',
                ),
              ),
            ] else ...[
              Text(
                widget.adapter is UnavailableVerifier
                    ? 'Sin validador configurado. No se enviarán datos reales.'
                    : 'Pega el enlace openid4vp:// emitido por el validador.',
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _input,
                autocorrect: false,
                enableSuggestions: false,
                decoration: const InputDecoration(
                  labelText: 'Enlace de verificación',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: _busy ? null : () => unawaited(_fetchRequest()),
                child: Text(
                  _busy && req == null ? 'Consultando…' : 'Consultar solicitud',
                ),
              ),
            ],
            if (req != null) ...[
              const SizedBox(height: 20),
              Card(
                color: const Color(0xfff3effb),
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Solicitud de verificación',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 6),
                      Text('Validador: ${req.clientId}'),
                      Text('Consulta: ${req.credentialQueryId}'),
                      Text('Expira: ${req.expiresAt.toIso8601String()}'),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 12),
              if (widget.credentials.isEmpty)
                const Text('No hay credenciales almacenadas en tu wallet.')
              else ...[
                Text(
                  'Selecciona una credencial',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                const SizedBox(height: 8),
                ...widget.credentials.map(
                  (cred) => CredentialCard(
                    credential: cred,
                    selected: cred.id == _selectedCredentialId,
                    onTap: _busy
                        ? null
                        : () => setState(() => _selectedCredentialId = cred.id),
                  ),
                ),
                const SizedBox(height: 12),
                FilledButton(
                  onPressed: _busy || _selectedCredential == null || _submitted
                      ? null
                      : () => unawaited(_submitPresentation()),
                  child: Text(_busy ? 'Enviando…' : 'Presentar'),
                ),
              ],
            ],
            if (_statusNote != null) ...[
              const SizedBox(height: 16),
              Semantics(liveRegion: true, child: Text(_statusNote!)),
            ],
            const SizedBox(height: 16),
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: Text(_submitted ? 'Volver' : 'Cancelar'),
            ),
          ],
        ),
      ),
    );
  }
}
