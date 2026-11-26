import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/credential_card.dart';
import 'package:hukid_wallet/keystore.dart';
import 'package:hukid_wallet/main.dart';
import 'package:material_ui/material_ui.dart';

String _jwt(Map<String, dynamic> subject) {
  final payload = base64Url.encode(utf8.encode(jsonEncode({'credentialSubject': subject}))).replaceAll('=', '');
  return 'e30.$payload.sig';
}

StoredCredential _credential(String vcJwt) => StoredCredential(
  id: 'cred_card_1',
  credentialIssuer: 'https://example.com/incubaunas',
  configurationId: 'attendance',
  title: 'Certificado de asistencia',
  issuerDisplayName: 'example.com/incubaunas',
  holderJkt: 'thumbprint_card_1',
  keyAlias: 'key_1',
  vcJwt: vcJwt,
  receivedAtIso: '2026-11-20T12:00:00Z',
);

final _nexo = _jwt({
  'recipient': {'displayName': 'Persona de Prueba', 'registrationId': 'reg-1'},
  'certificate': {'verificationCode': 'NX-TEST0001'},
  'event': {'id': 'event-demo'},
  'achievement': {'attendanceRate': 1},
});

void main() {
  test('reads holder and code from both certificate shapes', () {
    final nexo = CredentialSummary.fromVcJwt(_nexo);
    expect(nexo.holderName, 'Persona de Prueba');
    expect(nexo.code, 'NX-TEST0001');
    final canonical = CredentialSummary.fromVcJwt(_jwt({'participantName': 'Ana', 'certificateNumber': 'C-1'}));
    expect(canonical.holderName, 'Ana');
    expect(canonical.code, 'C-1');
  });

  test('unreadable content leaves the card without invented data', () {
    final summary = CredentialSummary.fromVcJwt('hdr.pay.sig');
    expect(summary.holderName, isNull);
    expect(summary.code, isNull);
    expect(summary.fields, isEmpty);
    expect(issuerInitial('example.com/incubaunas'), 'I');
    expect(issuerInitial(''), '?');
  });

  testWidgets('card opens the detail and never claims it is verified', (tester) async {
    final vault = MemoryCredentialVault();
    await vault.saveCredential(_credential(_nexo));
    await tester.pumpWidget(WalletApp(vault: vault));
    await tester.pumpAndSettle();
    expect(find.text('Persona de Prueba'), findsOneWidget);
    expect(find.text('NX-TEST0001'), findsOneWidget);
    expect(find.textContaining('thumbprint'), findsNothing);
    expect(find.textContaining('Verificada'), findsNothing);
    await tester.tap(find.text('Certificado de asistencia'));
    await tester.pumpAndSettle();
    expect(find.byType(CredentialDetailPage), findsOneWidget);
    await tester.scrollUntilVisible(find.text('thumbprint_card_1'), 200,
        scrollable: find.descendant(of: find.byType(CredentialDetailPage), matching: find.byType(Scrollable)).first);
    expect(find.text('thumbprint_card_1'), findsOneWidget);
  });

  testWidgets('card does not overflow on a narrow screen with large text', (tester) async {
    tester.view.physicalSize = const Size(640, 1200);
    tester.view.devicePixelRatio = 2;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(MaterialApp(
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context).copyWith(textScaler: const TextScaler.linear(2)),
        child: child!,
      ),
      home: Scaffold(body: ListView(children: [CredentialCard(credential: _credential(_nexo), selected: true)])),
    ));
    expect(tester.takeException(), isNull);
  });
}
