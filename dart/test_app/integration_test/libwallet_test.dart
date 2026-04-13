import 'dart:ffi';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:libwallet/libwallet.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  late LibwalletClient client;
  late Directory tempDir;

  setUpAll(() async {
    final appDir = await getApplicationDocumentsDirectory();
    tempDir = Directory('${appDir.path}/libwallet-test');
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
    tempDir.createSync();

    // Load the c-shared library via FFI — no platform channel needed.
    // On iOS the lib is statically linked into the app binary.
    // On Android it's a .so in the app's lib directory.
    final DynamicLibrary lib;
    if (Platform.isIOS) {
      lib = DynamicLibrary.process();
    } else if (Platform.isAndroid) {
      lib = DynamicLibrary.open('liblibwallet.so');
    } else {
      throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
    }

    client = LibwalletClient.initialize(tempDir.path, library: lib);
  });

  tearDownAll(() async {
    client.dispose();
    await Future.delayed(const Duration(milliseconds: 200));
    tempDir.deleteSync(recursive: true);
  });

  testWidgets('Info:ping responds', (tester) async {
    final result = await client.info.ping();
    expect(result, isNotNull);
  });

  testWidgets('Info:version returns a string', (tester) async {
    final version = await client.info.version();
    expect(version, isA<String>());
    expect(version, isNotEmpty);
  });

  testWidgets('Info:onboarding returns state', (tester) async {
    final state = await client.info.onboarding();
    expect(state.hasWallet, false);
  });

  testWidgets('Network list returns networks', (tester) async {
    final networks = await client.networks.list();
    expect(networks, isA<List<Network>>());
    expect(networks, isNotEmpty);
  });

  testWidgets('Wallet list is initially empty', (tester) async {
    final wallets = await client.wallets.list();
    expect(wallets, isEmpty);
  });

  testWidgets('create and delete a wallet with password-only keys',
      (tester) async {
    Wallet? createdWallet;
    await for (final event in client.wallets.create(
      name: 'Test Wallet',
      keys: [
        KeyDescription.password('test-pass-1'),
        KeyDescription.password('test-pass-2'),
        KeyDescription.password('test-pass-3'),
      ],
    )) {
      switch (event) {
        case Progress():
          break;
        case Complete(:final value):
          createdWallet = value;
      }
    }

    expect(createdWallet, isNotNull);
    expect(createdWallet!.name, 'Test Wallet');
    expect(createdWallet.keys, hasLength(3));

    // Create an account
    final account = await client.accounts.create(
      name: 'Test Account',
      wallet: createdWallet.id,
      type: 'ethereum',
      index: 0,
    );
    expect(account.address, isNotEmpty);

    // Clean up
    await client.wallets.delete(createdWallet.id);
    final afterDelete = await client.wallets.list();
    expect(afterDelete, isEmpty);
  });

  testWidgets('raw request works', (tester) async {
    final result = await client.rawRequest('Info:ping');
    expect(result, isNotNull);
  });
}
