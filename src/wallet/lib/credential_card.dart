import 'dart:convert';

import 'package:material_ui/material_ui.dart';

import 'keystore.dart';

/// Datos para mostrar una credencial, leídos de `credentialSubject`.
/// Es sólo presentación: no verifica firma, estado ni vigencia.
class CredentialSummary {
  const CredentialSummary({this.holderName, this.code, this.fields = const {}});

  factory CredentialSummary.fromVcJwt(String vcJwt) {
    try {
      final payload = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(vcJwt.split('.')[1]))),
      );
      final subject = (payload as Map<String, dynamic>)['credentialSubject'];
      final fields = <String, String>{};
      _flatten('', subject as Map<String, dynamic>, fields);
      return CredentialSummary(
        holderName: fields['recipient.displayName'] ?? fields['participantName'],
        code: fields['certificate.verificationCode'] ?? fields['certificateNumber'],
        fields: fields,
      );
    } catch (_) {
      return const CredentialSummary();
    }
  }

  final String? holderName;
  final String? code;

  /// Ruta del dato (por ejemplo `event.id`) y su valor.
  final Map<String, String> fields;

  static void _flatten(String prefix, Map<String, dynamic> node, Map<String, String> out) {
    for (final entry in node.entries) {
      final path = prefix.isEmpty ? entry.key : '$prefix.${entry.key}';
      final value = entry.value;
      if (value is Map<String, dynamic>) {
        _flatten(path, value, out);
      } else if (value is String || value is num || value is bool) {
        out[path] = '$value';
      }
    }
  }
}

const _fieldLabels = <String, String>{
  'recipient.displayName': 'Titular',
  'participantName': 'Titular',
  'certificate.verificationCode': 'Código',
  'certificateNumber': 'Número de certificado',
  'certificate.issuedAt': 'Fecha del certificado',
  'certificate.verificationUrl': 'Página de verificación',
  'certificate.evidenceDigest': 'Huella de evidencia',
  'certificate.id': 'Identificador del certificado',
  'recipient.registrationId': 'Identificador de inscripción',
  'event.id': 'Identificador del evento',
  'achievement.attendanceRate': 'Asistencia',
  'eventTitle': 'Evento',
  'eventDate': 'Fecha del evento',
  'organizerName': 'Organizador',
  'participationRole': 'Participación como',
};

String _display(String path, String value) {
  if (path == 'achievement.attendanceRate') {
    final rate = num.tryParse(value);
    if (rate != null && rate >= 0 && rate <= 1) return '${(rate * 100).round()} %';
  }
  return value;
}

const _months = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic'];

String credentialDate(String iso) {
  final date = DateTime.tryParse(iso)?.toLocal();
  return date == null ? iso : '${date.day} ${_months[date.month - 1]} ${date.year}';
}

/// Inicial del emisor: último tramo de su ruta (o el host), que es lo que la
/// wallet conoce. No usa logos ni nombres que no vengan del emisor validado.
String issuerInitial(String issuer) {
  final last = issuer.split('/').where((part) => part.isNotEmpty).lastOrNull;
  return last == null ? '?' : last.substring(0, 1).toUpperCase();
}

class CredentialCard extends StatelessWidget {
  const CredentialCard({
    super.key,
    required this.credential,
    this.onTap,
    this.selected,
  });

  final StoredCredential credential;
  final VoidCallback? onTap;

  /// Si no es null, la tarjeta se usa para elegir y muestra la selección.
  final bool? selected;

  @override
  Widget build(BuildContext context) {
    final summary = CredentialSummary.fromVcJwt(credential.vcJwt);
    final text = Theme.of(context).textTheme;
    const soft = Color(0xffe4daff);
    final radius = BorderRadius.circular(20);
    return Semantics(
      button: onTap != null,
      selected: selected,
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: DecoratedBox(
          decoration: BoxDecoration(
            borderRadius: radius,
            gradient: const LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xff5027bc), Color(0xff2a1464)],
            ),
            border: Border.all(
              color: selected == true ? const Color(0xffffc857) : Colors.transparent,
              width: 3,
            ),
          ),
          child: Material(
            type: MaterialType.transparency,
            child: InkWell(
              borderRadius: radius,
              onTap: onTap,
              child: Padding(
                padding: const EdgeInsets.all(20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        CircleAvatar(
                          backgroundColor: Colors.white,
                          foregroundColor: const Color(0xff5027bc),
                          child: ExcludeSemantics(
                            child: Text(issuerInitial(credential.issuerDisplayName)),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            credential.issuerDisplayName,
                            style: text.bodySmall?.copyWith(color: soft),
                          ),
                        ),
                        if (selected != null)
                          Icon(
                            selected! ? Icons.radio_button_checked : Icons.radio_button_unchecked,
                            color: Colors.white,
                          ),
                      ],
                    ),
                    const SizedBox(height: 20),
                    Text(
                      credential.title,
                      style: text.titleLarge?.copyWith(color: Colors.white),
                    ),
                    if (summary.holderName != null) ...[
                      const SizedBox(height: 6),
                      Text(
                        summary.holderName!,
                        style: text.titleMedium?.copyWith(color: soft),
                      ),
                    ],
                    const SizedBox(height: 20),
                    SizedBox(
                      width: double.infinity,
                      child: Wrap(
                        alignment: WrapAlignment.spaceBetween,
                        spacing: 12,
                        runSpacing: 4,
                        children: [
                          if (summary.code != null)
                            Text(summary.code!, style: text.bodyMedium?.copyWith(color: Colors.white)),
                          Text(
                            'Recibida ${credentialDate(credential.receivedAtIso)}',
                            style: text.bodySmall?.copyWith(color: soft),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class CredentialDetailPage extends StatelessWidget {
  const CredentialDetailPage({super.key, required this.credential, this.onShowPass});

  final StoredCredential credential;

  /// Presente sólo si la credencial sirve para el ingreso.
  final VoidCallback? onShowPass;

  @override
  Widget build(BuildContext context) {
    final summary = CredentialSummary.fromVcJwt(credential.vcJwt);
    Widget row(String label, String value) => Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: Theme.of(context).textTheme.labelMedium),
          const SizedBox(height: 2),
          Text(value, style: Theme.of(context).textTheme.bodyLarge),
        ],
      ),
    );
    return Scaffold(
      appBar: AppBar(title: const Text('Detalle')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(24),
          children: [
            CredentialCard(credential: credential),
            const SizedBox(height: 16),
            if (onShowPass != null) ...[
              FilledButton.icon(
                icon: const Icon(Icons.qr_code),
                onPressed: onShowPass,
                label: const Text('Mostrar para ingresar'),
              ),
              const SizedBox(height: 24),
            ],
            for (final field in summary.fields.entries)
              row(_fieldLabels[field.key] ?? field.key, _display(field.key, field.value)),
            const Divider(),
            const SizedBox(height: 16),
            row('Emisor', credential.credentialIssuer),
            row('Llave vinculada', credential.holderJkt),
            const Text(
              'Estos datos son los que contiene la credencial guardada. Esta vista '
              'no comprueba su estado ni su vigencia actual.',
            ),
          ],
        ),
      ),
    );
  }
}
