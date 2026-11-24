import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/crypto_p256.dart';
import 'package:hukid_wallet/issuance.dart';
import 'package:hukid_wallet/keystore.dart';
import 'package:hukid_wallet/main.dart';
import 'package:hukid_wallet/oid4vp_client.dart';
import 'package:material_ui/material_ui.dart';

import 'issuance_test.dart' show TestIssuer;

Future<void> openOffer(WidgetTester tester, OfferAdapter adapter, {CredentialVault? vault}) async {
  await tester.pumpWidget(WalletApp(adapter: adapter, vault: vault));
  await tester.tap(find.text('Recibir credencial'));
  await tester.pumpAndSettle();
  await tester.enterText(find.byType(TextField), 'test:offer');
  await tester.tap(find.text('Revisar oferta'));
  await tester.pumpAndSettle();
}

Finder pageListScrollable(Finder page) {
  expect(page, findsOneWidget);
  final list = find.descendant(of: page, matching: find.byType(ListView));
  expect(list, findsOneWidget);
  final scrollable = find.descendant(
    of: list,
    matching: find.byWidgetPredicate(
      (widget) =>
          widget is Scrollable && widget.axisDirection == AxisDirection.down,
    ),
  );
  expect(scrollable, findsOneWidget);
  return scrollable;
}

void main() {
  testWidgets('preview, consent and repeated tap handle failure cleanly', (
    tester,
  ) async {
    final adapter = TestIssuer();
    await openOffer(tester, adapter);
    expect(find.text('Emisor de prueba'), findsOneWidget);
    expect(adapter.requests, 0);
    await tester.tap(find.text('Solicitar recepción'));
    await tester.pump();
    expect(adapter.requests, 0);
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pump();
    await tester.tap(find.text('Solicitar recepción'));
    await tester.pump();
    expect(adapter.requests, 1);
    expect(find.text('Recepción pendiente'), findsOneWidget);
    adapter.response.completeError(StateError('offline'));
    await tester.pumpAndSettle();
    expect(find.text('Recepción no disponible'), findsOneWidget);
    expect(find.text('No se guardó ninguna credencial.'), findsOneWidget);
  });

  testWidgets('stored outcome shows confirmation and updates WalletHome count', (
    tester,
  ) async {
    final adapter = TestIssuer();
    final vault = MemoryCredentialVault();
    await openOffer(tester, adapter, vault: vault);
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pump();
    await tester.tap(find.text('Solicitar recepción'));
    await tester.pump();

    const cred = StoredCredential(
      id: 'cred_test_1',
      credentialIssuer: 'https://issuer.hukid.pe/unas',
      configurationId: 'event_participation_v1',
      title: 'Taller ficticio',
      issuerDisplayName: 'Emisor de prueba',
      holderJkt: 'thumbprint_123456',
      keyAlias: 'hukid_key_1',
      vcJwt: 'hdr.pay.sig',
      receivedAtIso: '2026-11-20T12:00:00Z',
    );
    await vault.saveCredential(cred);
    adapter.response.complete(const ReceiveOutcome.stored(cred));
    await tester.pumpAndSettle();

    expect(find.text('Credencial guardada'), findsOneWidget);
    await tester.tap(find.text('Volver'));
    await tester.pumpAndSettle();
    expect(find.text('1 credencial'), findsOneWidget);
    expect(find.text('Taller ficticio'), findsOneWidget);
  });

  testWidgets('cancel and Android back have no request side effects', (
    tester,
  ) async {
    final adapter = TestIssuer();
    await openOffer(tester, adapter);
    await tester.tap(find.text('Cancelar'));
    await tester.pumpAndSettle();
    expect(find.text('Mi wallet'), findsOneWidget);
    expect(adapter.requests, 0);
    await tester.tap(find.text('Recibir credencial'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'test:offer');
    await tester.tap(find.text('Revisar oferta'));
    await tester.pumpAndSettle();
    await tester.binding.handlePopRoute();
    await tester.pumpAndSettle();
    expect(find.text('Mi wallet'), findsOneWidget);
    expect(adapter.requests, 0);
  });

  testWidgets('runtime is empty and explains missing issuer at large text', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(640, 1200);
    tester.view.devicePixelRatio = 2;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(
      MaterialApp(
        builder: (context, child) => MediaQuery(
          data: MediaQuery.of(context)
              .copyWith(textScaler: const TextScaler.linear(2)),
          child: child!,
        ),
        home: const WalletHome(),
      ),
    );
    expect(find.text('0 credenciales'), findsOneWidget);
    final receiveBtn = find.widgetWithText(FilledButton, 'Recibir credencial');
    await tester.scrollUntilVisible(
      receiveBtn,
      200,
      scrollable: pageListScrollable(find.byType(WalletHome)),
    );
    await tester.ensureVisible(receiveBtn);
    await tester.pumpAndSettle();
    await tester.tap(receiveBtn);
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'https://unknown.example');
    final previewBtn = find.widgetWithText(FilledButton, 'Revisar oferta');
    await tester.scrollUntilVisible(
      previewBtn,
      200,
      scrollable: pageListScrollable(find.byType(ReceivePage)),
    );
    await tester.ensureVisible(previewBtn);
    await tester.pumpAndSettle();
    await tester.tap(previewBtn);
    await tester.pumpAndSettle();
    await tester.scrollUntilVisible(
      find.text('No se guardó ninguna credencial.'),
      200,
      scrollable: pageListScrollable(find.byType(ReceivePage)),
    );
    expect(
      find.text('Sin emisor configurado. Integración no disponible.'),
      findsOneWidget,
    );
    expect(find.text('No se guardó ninguna credencial.'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('WalletHome navigates to PresentPage and submits presentation', (
    tester,
  ) async {
    final fakeVerifier = _FakePresentationAdapter();
    final vault = MemoryCredentialVault();
    const cred = StoredCredential(
      id: 'cred_vp_ui_1',
      credentialIssuer: 'https://issuer.hukid.pe/unas',
      configurationId: 'event_participation_v1',
      title: 'Certificado UNAS',
      issuerDisplayName: 'UNAS Cloud',
      holderJkt: 'thumbprint_ui_1',
      keyAlias: 'hukid_key_ui_1',
      vcJwt: 'hdr.pay.sig',
      receivedAtIso: '2026-11-23T12:00:00Z',
    );
    await vault.saveCredential(cred);

    await tester.pumpWidget(
      WalletApp(
        presentationAdapter: fakeVerifier,
        vault: vault,
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('Presentar credencial'));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byType(TextField),
      'openid4vp://authorize?client_id=x509_san_dns%3Ahukid.zentrycore.com&request_uri=https%3A%2F%2Fhukid.zentrycore.com%2Foid4vp%2Frequest%2Fs1',
    );
    await tester.tap(find.text('Consultar solicitud'));
    await tester.pumpAndSettle();

    expect(find.text('Certificado UNAS'), findsOneWidget);
    expect(find.text('Consulta: event_cred'), findsOneWidget);
    final presentBtn = find.widgetWithText(FilledButton, 'Presentar');
    await tester.scrollUntilVisible(
      presentBtn,
      200,
      scrollable: pageListScrollable(find.byType(PresentPage)),
    );
    await tester.ensureVisible(presentBtn);
    await tester.pumpAndSettle();
    await tester.tap(presentBtn);
    await tester.pumpAndSettle();

    final sentText = find.text('Presentación enviada al validador.');
    await tester.scrollUntilVisible(
      sentText,
      200,
      scrollable: pageListScrollable(find.byType(PresentPage)),
    );
    expect(sentText, findsOneWidget);
    expect(fakeVerifier.presentedCredential?.id, 'cred_vp_ui_1');
  });
}

class _FakePresentationAdapter implements PresentationAdapter {
  StoredCredential? presentedCredential;

  @override
  Future<PresentationRequestSummary> fetchRequest(String launchUri) async {
    final enc = P256KeyPair.generate(kid: 'enc-k1').publicJwk;
    return PresentationRequestSummary(
      clientId: 'x509_san_dns:hukid.zentrycore.com',
      requestUri: Uri.parse('https://hukid.zentrycore.com/oid4vp/request/s1'),
      responseUri: Uri.parse('https://hukid.zentrycore.com/oid4vp/response'),
      state: 's1',
      nonce: 'n1',
      credentialQueryId: 'event_cred',
      encryptionKey: enc,
      expiresAt: DateTime.utc(2027, 1, 1),
      signatureVerified: true,
    );
  }

  @override
  Future<PresentationOutcome> presentCredential({
    required PresentationRequestSummary request,
    required StoredCredential credential,
  }) async {
    presentedCredential = credential;
    return const PresentationOutcome(state: PresentationState.submitted);
  }
}
