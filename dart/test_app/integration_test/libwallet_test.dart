import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:libwallet/libwallet.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  late LibwalletClient client;

  setUpAll(() async {
    const channel = MethodChannel('com.libwallet');

    // Get the app's documents directory for data storage
    final appDir = await getApplicationDocumentsDirectory();
    final appDirPath = appDir.path;

    // Determine socket path, respecting iOS MAX_PATH (104 bytes) for Unix sockets
    const sockName = 'ipc.sock';
    String sockPath = '$appDirPath/$sockName';
    String passedPath = sockPath;

    if (Platform.isIOS && sockPath.length > 104) {
      // Path too long for Unix socket on iOS -- use relative path
      // The Go library will resolve it relative to dataDir
      passedPath = sockName;
      sockPath = sockName;
      // Change working directory so relative socket path works
      Directory.current = appDirPath;
    }

    // Start the Go library via platform channel
    await channel.invokeMethod('makeSocket', {
      'path': passedPath,
      'appDir': appDirPath,
    });

    // Give the Go listener time to start
    await Future.delayed(const Duration(milliseconds: 500));

    // Connect
    client = await LibwalletClient.connect(sockPath);
  });

  tearDownAll(() async {
    client.dispose();
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

  testWidgets('Account list is initially empty', (tester) async {
    final accounts = await client.accounts.list();
    expect(accounts, isEmpty);
  });

  testWidgets('Contact list is initially empty', (tester) async {
    final contacts = await client.contacts.list();
    expect(contacts, isEmpty);
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
    expect(createdWallet.curve, 'secp256k1');
    expect(createdWallet.keys, hasLength(3));
    expect(createdWallet.isUnsafe, true);

    // Verify it shows up in the list
    final wallets = await client.wallets.list();
    expect(wallets, hasLength(1));
    expect(wallets.first.id, createdWallet.id);

    // Create an account
    final account = await client.accounts.create(
      name: 'Test Account',
      wallet: createdWallet.id,
      type: 'ethereum',
      index: 0,
    );
    expect(account.address, isNotEmpty);
    expect(account.type, 'ethereum');

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
