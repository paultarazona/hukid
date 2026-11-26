import 'dart:convert';
import 'dart:io';

import 'crypto_p256.dart';

/// Confianza del verificador local de laboratorio (ADR-0037), fijada al
/// compilar. No es el mecanismo de confianza de producción.
class LabVerifierTrust {
  const LabVerifierTrust({required this.signingKeys, required this.caPem, required this.origin});

  final Map<String, PublicEcJwk> signingKeys;
  final List<int> caPem;
  final String origin;

  /// Devuelve null si no se pasó la configuración completa o no es válida, o si
  /// la compilación no habilita el laboratorio. El origen debe ser loopback.
  static LabVerifierTrust? parse({
    required bool labEnabled,
    required String jwkBase64,
    required String caBase64,
    required String origin,
  }) {
    if (!labEnabled || jwkBase64.isEmpty || caBase64.isEmpty) return null;
    try {
      final uri = Uri.parse(origin);
      if (uri.scheme != 'https' || uri.host != '127.0.0.1' || !uri.hasPort || uri.path.isNotEmpty) {
        return null;
      }
      final jwk = jsonDecode(utf8.decode(base64.decode(jwkBase64))) as Map<String, dynamic>;
      final key = PublicEcJwk.fromJson(jwk);
      final kid = key.kid;
      if (kid == null || kid.isEmpty) return null;
      return LabVerifierTrust(signingKeys: {kid: key}, caPem: base64.decode(caBase64), origin: origin);
    } catch (_) {
      return null;
    }
  }

  /// Cliente HTTP que, además de las raíces del sistema, confía en la CA de
  /// laboratorio. Sólo lo usa el cliente de presentación.
  HttpClient httpClient() => HttpClient(
    context: SecurityContext(withTrustedRoots: true)..setTrustedCertificatesBytes(caPem),
  );
}

const String _jwk = String.fromEnvironment('HUKID_LAB_VERIFIER_JWK');
const String _ca = String.fromEnvironment('HUKID_LAB_VERIFIER_CA');
const String _origin = String.fromEnvironment(
  'HUKID_LAB_VERIFIER_ORIGIN',
  defaultValue: 'https://127.0.0.1:8443',
);

LabVerifierTrust? labVerifierFromEnvironment({required bool labEnabled}) =>
    LabVerifierTrust.parse(labEnabled: labEnabled, jwkBase64: _jwk, caBase64: _ca, origin: _origin);
