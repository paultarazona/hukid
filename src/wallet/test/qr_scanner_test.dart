import 'package:flutter_test/flutter_test.dart';
import 'package:hukid_wallet/issuance.dart';
import 'package:hukid_wallet/main.dart';
import 'package:hukid_wallet/qr_scanner.dart';
import 'package:material_ui/material_ui.dart';

class _Scanner implements QrScanner {
  _Scanner(this.result);

  final Future<String?> Function() result;

  @override
  Future<String?> scan() => result();
}

class _Issuer extends UnavailableIssuer {
  _Issuer(this.links);

  final List<String> links;

  @override
  OfferPreview? preview(String link) {
    links.add(link);
    return const OfferPreview(issuer: 'Emisor de prueba', title: 'Taller ficticio');
  }
}

const offerLink = 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fexample.com%2Fo';
const verifyLink = 'openid4vp://authorize?client_id=x';

Future<List<String>> scanOn(
  WidgetTester tester,
  String screen,
  Future<String?> Function() result,
) async {
  final links = <String>[];
  await tester.pumpWidget(WalletApp(adapter: _Issuer(links), scanner: _Scanner(result)));
  await tester.tap(find.text(screen));
  await tester.pumpAndSettle();
  expect(find.byType(TextField), findsNothing);
  await tester.tap(find.text('Escanear QR'));
  await tester.pumpAndSettle();
  return links;
}

void main() {
  testWidgets('scanning an offer shows its preview without showing the link', (tester) async {
    final links = await scanOn(tester, 'Recibir credencial', () async => offerLink);
    expect(links, [offerLink]);
    expect(find.text('Emisor de prueba'), findsOneWidget);
    expect(find.textContaining('openid-credential-offer'), findsNothing);
  });

  testWidgets('receive rejects a verification QR', (tester) async {
    final links = await scanOn(tester, 'Recibir credencial', () async => verifyLink);
    expect(links, isEmpty);
    expect(find.textContaining('Usa «Presentar credencial»'), findsOneWidget);
  });

  testWidgets('present rejects an offer QR', (tester) async {
    await scanOn(tester, 'Presentar credencial', () async => offerLink);
    expect(find.textContaining('Usa «Recibir credencial»'), findsOneWidget);
  });

  testWidgets('cancelling the scanner changes nothing', (tester) async {
    final links = await scanOn(tester, 'Recibir credencial', () async => null);
    expect(links, isEmpty);
    expect(find.text('Escanear QR'), findsOneWidget);
    expect(find.text('Recepción no disponible'), findsNothing);
  });

  testWidgets('scanner failure is explained and can be retried', (tester) async {
    await scanOn(tester, 'Recibir credencial', () async => throw StateError('no module'));
    expect(find.text(qrScannerFailureMessage), findsOneWidget);
    expect(find.text('Escanear QR'), findsOneWidget);
  });
}
