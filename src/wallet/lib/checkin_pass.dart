import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:material_ui/material_ui.dart';
import 'package:qr/qr.dart';

import 'credential_card.dart';
import 'crypto_p256.dart';
import 'keystore.dart';
import 'oid4vci_client.dart';

/// Pase de ingreso (ADR-0038): código temporal de un solo uso que la wallet
/// muestra como QR. No contiene la credencial ni datos personales.
class CheckinPass {
  const CheckinPass({required this.code, required this.expiresAt});

  final String code;
  final DateTime expiresAt;

  String get qrText => 'hukid-pass://v1?code=${Uri.encodeQueryComponent(code)}';
}

class PassException implements Exception {
  const PassException(this.message);

  final String message;
}

abstract interface class PassIssuer {
  Future<CheckinPass> create(StoredCredential credential);
}

/// Una credencial sirve para el ingreso si trae la inscripción y el evento.
bool supportsCheckinPass(StoredCredential credential) {
  final fields = CredentialSummary.fromVcJwt(credential.vcJwt).fields;
  return (fields['recipient.registrationId']?.isNotEmpty ?? false) &&
      (fields['event.id']?.isNotEmpty ?? false);
}

class HukidPassClient implements PassIssuer {
  HukidPassClient({
    required HolderKeyStore keyStore,
    Oid4vciHttpClient? httpClient,
    Oid4vciConfig config = const Oid4vciConfig(),
  }) : _keyStore = keyStore,
       _http = httpClient ?? IoOid4vciHttpClient(),
       _config = config;

  final HolderKeyStore _keyStore;
  final Oid4vciHttpClient _http;
  final Oid4vciConfig _config;

  static const _unavailable =
      'No se pudo crear el pase. Revisa tu conexión e inténtalo otra vez.';

  /// La dirección sale del emisor de la credencial guardada, nunca de un QR.
  Uri _endpoint(StoredCredential credential, String path) {
    final issuer = Uri.tryParse(credential.credentialIssuer);
    final loopback = const {'127.0.0.1', 'localhost', '::1'}.contains(issuer?.host);
    if (issuer == null ||
        issuer.host.isEmpty ||
        issuer.userInfo.isNotEmpty ||
        !(issuer.scheme == 'https' ||
            (issuer.scheme == 'http' && _config.allowInsecureLoopback && loopback))) {
      throw const PassException('El emisor de esta credencial no tiene una dirección segura.');
    }
    return Uri(
      scheme: issuer.scheme,
      host: issuer.host,
      port: issuer.hasPort ? issuer.port : null,
      path: path,
    );
  }

  Future<Map<String, dynamic>> _post(Uri uri, Map<String, dynamic> body, int expected) async {
    final response = await _http.post(
      uri,
      headers: const <String, String>{HttpHeaders.contentTypeHeader: 'application/json'},
      body: jsonEncode(body),
    );
    if (response.statusCode != expected) {
      throw PassException(switch (response.statusCode) {
        403 => 'HukID no aceptó esta credencial. Puede haber sido revocada o reemplazada.',
        422 => 'Esta credencial no sirve para el ingreso.',
        429 => 'Hay demasiadas solicitudes. Espera unos segundos.',
        _ => _unavailable,
      });
    }
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  @override
  Future<CheckinPass> create(StoredCredential credential) async {
    try {
      final target = _endpoint(credential, '/v1/passes');
      final challenge = await _post(_endpoint(credential, '/v1/passes/nonce'), const {}, 200);
      final key = await _keyStore.ensureKey(credential.keyAlias);
      if (key.thumbprint() != credential.holderJkt) {
        throw const PassException('La clave de esta credencial ya no está en este teléfono.');
      }
      final presentation = await buildVerifiablePresentationJwt(
        holderPublicJwk: key,
        signEs256: (bytes) => _keyStore.signEs256(credential.keyAlias, bytes),
        audience: target.toString(),
        nonce: challenge['nonce'] as String,
        credentials: <String>[credential.vcJwt],
      );
      final pass = await _post(target, {'presentation': presentation}, 201);
      return CheckinPass(
        code: pass['code'] as String,
        expiresAt: DateTime.parse(pass['expiresAt'] as String),
      );
    } on PassException {
      rethrow;
    } catch (_) {
      // Nunca mostrar el error crudo: puede contener la presentación.
      throw const PassException(_unavailable);
    }
  }
}

class PassPage extends StatefulWidget {
  const PassPage({super.key, required this.issuer, required this.credential, this.now});

  final PassIssuer issuer;
  final StoredCredential credential;
  final DateTime Function()? now;

  @override
  State<PassPage> createState() => _PassPageState();
}

class _PassPageState extends State<PassPage> {
  CheckinPass? _pass;
  String? _error;
  bool _busy = false;
  Timer? _clock;

  DateTime _now() => widget.now?.call() ?? DateTime.now();

  @override
  void initState() {
    super.initState();
    unawaited(_create());
  }

  @override
  void dispose() {
    _clock?.cancel();
    super.dispose();
  }

  Future<void> _create() async {
    if (_busy) return;
    _clock?.cancel();
    setState(() {
      _busy = true;
      _pass = null;
      _error = null;
    });
    try {
      final pass = await widget.issuer.create(widget.credential);
      if (!mounted) return;
      setState(() => _pass = pass);
      _clock = Timer.periodic(const Duration(seconds: 1), (timer) {
        if (!_now().isBefore(pass.expiresAt)) timer.cancel();
        if (mounted) setState(() {});
      });
    } on PassException catch (error) {
      if (mounted) setState(() => _error = error.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final pass = _pass;
    final seconds = pass == null ? 0 : pass.expiresAt.difference(_now()).inSeconds;
    final live = pass != null && seconds > 0;
    return Scaffold(
      appBar: AppBar(title: const Text('Mostrar para ingresar')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            Text(widget.credential.title, style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 16),
            if (_busy) const Text('Creando tu pase…'),
            if (live) ...[
              Center(child: PassQr(data: pass.qrText)),
              const SizedBox(height: 16),
              const Text('Muestra este QR en la puerta. Sirve una sola vez.'),
              Semantics(liveRegion: false, child: Text('Vence en $seconds s')),
            ],
            if (pass != null && !live) const Text('Este pase venció.'),
            if (_error != null) Semantics(liveRegion: true, child: Text(_error!)),
            const SizedBox(height: 16),
            if (!_busy && !live)
              FilledButton(onPressed: () => unawaited(_create()), child: const Text('Generar otro')),
            TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Cerrar')),
          ],
        ),
      ),
    );
  }
}

class PassQr extends StatelessWidget {
  const PassQr({super.key, required this.data});

  final String data;

  @override
  Widget build(BuildContext context) => Semantics(
    image: true,
    label: 'Código QR de ingreso',
    child: ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 320),
      child: AspectRatio(
        aspectRatio: 1,
        child: CustomPaint(
          painter: _QrPainter(
            QrImage(QrCode.fromData(data: data, errorCorrectLevel: QrErrorCorrectLevel.M)),
            data,
          ),
        ),
      ),
    ),
  );
}

class _QrPainter extends CustomPainter {
  _QrPainter(this.image, this.data);

  final QrImage image;
  final String data;

  @override
  void paint(Canvas canvas, Size size) {
    // Siempre negro sobre blanco con zona de silencio de 4 módulos.
    canvas.drawRect(Offset.zero & size, Paint()..color = const Color(0xffffffff));
    final module = size.width / (image.moduleCount + 8);
    final dark = Paint()
      ..color = const Color(0xff000000)
      ..isAntiAlias = false;
    for (var row = 0; row < image.moduleCount; row++) {
      for (var col = 0; col < image.moduleCount; col++) {
        if (image.isDark(row, col)) {
          canvas.drawRect(
            Rect.fromLTWH((col + 4) * module, (row + 4) * module, module + 0.3, module + 0.3),
            dark,
          );
        }
      }
    }
  }

  @override
  bool shouldRepaint(_QrPainter old) => old.data != data;
}
