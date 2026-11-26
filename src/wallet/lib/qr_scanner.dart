import 'package:flutter/services.dart';

/// Lee un código QR. Devuelve su texto, o null si la persona cancela.
abstract interface class QrScanner {
  Future<String?> scan();
}

/// Escáner de códigos de Google Play services (ver MainActivity.kt). La cámara
/// la maneja Google Play services: la wallet no pide el permiso CAMERA.
class AndroidQrScanner implements QrScanner {
  const AndroidQrScanner();

  static const _channel = MethodChannel('dev.example.hukid_wallet/scanner');

  @override
  Future<String?> scan() => _channel.invokeMethod<String>('scanQr');
}

const String qrScannerFailureMessage =
    'No se pudo abrir el escáner. La primera vez, Google Play services puede '
    'necesitar descargarlo: revisa tu conexión a internet e inténtalo otra vez.';
