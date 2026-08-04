import 'package:flutter_test/flutter_test.dart';
import 'package:keyvault_mobile/main.dart';

void main() {
  testWidgets('KeyVault app boots to auth gate', (tester) async {
    await tester.pumpWidget(const KeyVaultApp());
    expect(find.text('KeyVault'), findsOneWidget);
    expect(find.text('Unlock'), findsWidgets);
  });
}
