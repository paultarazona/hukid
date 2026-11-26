import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/checkin_pass.dart';
import 'package:hukid_wallet/keystore.dart';
import 'package:hukid_wallet/main.dart';
import 'package:hukid_wallet/oid4vci_client.dart';
import 'package:material_ui/material_ui.dart';

class _Http implements Oid4vciHttpClient {
  _Http({this.passStatus = 201});

  final int passStatus;
  final List<Uri> posts = <Uri>[];
  String? presentation;

  @override
  Future<Oid4vciHttpResponse> get(
    Uri uri, {
    Map<String, String>? headers,
  }) async => const Oid4vciHttpResponse(statusCode: 404, body: '');

  @override
  Future<Oid4vciHttpResponse> post(
    Uri uri, {
    required Map<String, String> headers,
    required String body,
  }) async {
    posts.add(uri);
    if (uri.path.endsWith('/v1/passes/nonce')) {
      return const Oid4vciHttpResponse(
        statusCode: 200,
        body: '{"nonce":"nonce-1"}',
      );
    }
    presentation =
        (jsonDecode(body) as Map<String, dynamic>)['presentation'] as String;
    return Oid4vciHttpResponse(
      statusCode: passStatus,
      body: '{"code":"code-1","expiresAt":"2026-11-26T10:01:00Z"}',
    );
  }
}

String _jwt(Map<String, dynamic> subject) =>
    'e30.${base64Url.encode(utf8.encode(jsonEncode({'credentialSubject': subject}))).replaceAll('=', '')}.sig';

const _checkin = <String, dynamic>{
  'recipient': {'registrationId': 'reg-1', 'displayName': 'Persona de Prueba'},
  'event': {'id': 'event-1'},
};

StoredCredential _credential(
  String jkt, {
  String issuer = 'https://hukid.example/unas',
  Map<String, dynamic> subject = _checkin,
}) => StoredCredential(
  id: 'cred_pass',
  credentialIssuer: issuer,
  configurationId: 'participation',
  title: 'Participación',
  issuerDisplayName: 'hukid.example/unas',
  holderJkt: jkt,
  keyAlias: 'key_pass',
  vcJwt: _jwt(subject),
  receivedAtIso: '2026-11-26T10:00:00Z',
);

Map<String, dynamic> _part(String jwt, int index) => jsonDecode(
  utf8.decode(base64Url.decode(base64Url.normalize(jwt.split('.')[index]))),
) as Map<String, dynamic>;

class _Issuer implements PassIssuer {
  int calls = 0;
  PassException? error;

  @override
  Future<CheckinPass> create(StoredCredential credential) async {
    calls++;
    if (error != null) throw error!;
    return CheckinPass(
      code: 'code-$calls',
      expiresAt: DateTime.utc(2026, 11, 26, 10, calls),
    );
  }
}

void main() {
  test(
    'creates a pass with a holder presentation bound to the issuer origin',
    () async {
      final keys = MemoryHolderKeyStore();
      final jkt = (await keys.ensureKey('key_pass')).thumbprint();
      final http = _Http();
      final pass = await HukidPassClient(
        keyStore: keys,
        httpClient: http,
      ).create(_credential(jkt));
      expect(pass.qrText, 'hukid-pass://v1?code=code-1');
      expect(http.posts.map((u) => u.toString()), [
        'https://hukid.example/v1/passes/nonce',
        'https://hukid.example/v1/passes',
      ]);
      final payload = _part(http.presentation!, 1);
      expect(payload['aud'], 'https://hukid.example/v1/passes');
      expect(payload['nonce'], 'nonce-1');
      expect(_part(http.presentation!, 0)['typ'], 'vp+jwt');
    },
  );

  test('refuses insecure issuers and a different holder key without sending the credential', () async {
    final keys = MemoryHolderKeyStore();
    final jkt = (await keys.ensureKey('key_pass')).thumbprint();
    for (final issuer in [
      'http://hukid.example/unas',
      'http://127.0.0.1:8080/unas',
    ]) {
      final http = _Http();
      await expectLater(
        HukidPassClient(
          keyStore: keys,
          httpClient: http,
        ).create(_credential(jkt, issuer: issuer)),
        throwsA(isA<PassException>()),
      );
      expect(http.posts, isEmpty);
    }
    final lab = _Http();
    await HukidPassClient(
      keyStore: keys,
      httpClient: lab,
      config: const Oid4vciConfig(allowInsecureLoopback: true),
    ).create(_credential(jkt, issuer: 'http://127.0.0.1:8080/unas'));
    expect(lab.posts.last.toString(), 'http://127.0.0.1:8080/v1/passes');
    final http = _Http();
    await expectLater(
      HukidPassClient(
        keyStore: keys,
        httpClient: http,
      ).create(_credential('otro-jkt')),
      throwsA(isA<PassException>()),
    );
    expect(http.presentation, isNull);
  });

  test('explains a rejection', () async {
    final keys = MemoryHolderKeyStore();
    final jkt = (await keys.ensureKey('key_pass')).thumbprint();
    await expectLater(
      HukidPassClient(
        keyStore: keys,
        httpClient: _Http(passStatus: 403),
      ).create(_credential(jkt)),
      throwsA(
        isA<PassException>().having(
          (e) => e.message,
          'message',
          contains('no aceptó'),
        ),
      ),
    );
  });

  test('only credentials with registration and event support check-in', () {
    expect(supportsCheckinPass(_credential('j')), isTrue);
    expect(
      supportsCheckinPass(
        _credential(
          'j',
          subject: {
            'ticket': {
              'registrationId': 'reg-legacy',
              'eventId': 'event-legacy',
            },
          },
        ),
      ),
      isTrue,
    );
    expect(
      supportsCheckinPass(
        _credential(
          'j',
          subject: {
            'event': {'id': 'e'},
          },
        ),
      ),
      isFalse,
    );
    expect(supportsCheckinPass(_credential('j', subject: {})), isFalse);
  });

  testWidgets('pass page shows the QR, expires it and creates another', (
    tester,
  ) async {
    var now = DateTime.utc(2026, 11, 26, 10, 0, 0);
    final issuer = _Issuer();
    await tester.pumpWidget(
      MaterialApp(
        home: PassPage(
          issuer: issuer,
          credential: _credential('j'),
          now: () => now,
        ),
      ),
    );
    await tester.pump();
    expect(find.byType(PassQr), findsOneWidget);
    expect(find.text('Vence en 60 s'), findsOneWidget);
    expect(find.textContaining('code-1'), findsNothing);
    now = DateTime.utc(2026, 11, 26, 10, 1, 1);
    await tester.pump(const Duration(seconds: 1));
    expect(find.byType(PassQr), findsNothing);
    expect(find.text('Este pase venció.'), findsOneWidget);
    await tester.tap(find.text('Generar otro'));
    await tester.pump();
    expect(issuer.calls, 2);
    expect(find.byType(PassQr), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('wallet offers the pass from the detail only', (tester) async {
    final vault = MemoryCredentialVault();
    await vault.saveCredential(_credential('j'));
    final issuer = _Issuer()
      ..error = const PassException(
        'Esta credencial no sirve para el ingreso.',
      );
    await tester.pumpWidget(WalletApp(vault: vault, passIssuer: issuer));
    await tester.pumpAndSettle();
    expect(find.text('Mostrar para ingresar'), findsNothing);
    await tester.tap(find.text('Participación'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Mostrar para ingresar'));
    await tester.pumpAndSettle();
    expect(
      find.text('Esta credencial no sirve para el ingreso.'),
      findsOneWidget,
    );
    expect(find.byType(PassQr), findsNothing);
  });
}
