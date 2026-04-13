@TestOn('vm')
@Timeout(Duration(seconds: 60))
library;

import 'dart:ffi';
import 'dart:io';

import 'package:test/test.dart';
import 'package:libwallet/libwallet.dart';

/// Integration tests using the FFI transport (no sockets).
/// Requires the c-shared library to be built first:
///   cd .. && go build -buildmode=c-shared -o dart/testserver/liblibwallet.dylib ./cshared/
void main() {
  late LibwalletClient client;
  late Directory tempDir;

  setUpAll(() {
    final libPath = '${Directory.current.path}/testserver/liblibwallet.dylib';
    if (!File(libPath).existsSync()) {
      fail('liblibwallet.dylib not found at $libPath\n'
          'Build it first: cd .. && go build -buildmode=c-shared -o dart/testserver/liblibwallet.dylib ./cshared/');
    }

    tempDir = Directory.systemTemp.createTempSync('libwallet-ffi-test-');

    final lib = DynamicLibrary.open(libPath);
    client = LibwalletClient.initialize(tempDir.path, library: lib);
  });

  tearDownAll(() async {
    // Don't call client.dispose() in tests — the Go c-shared runtime's
    // goroutine cleanup races with Dart's isolate shutdown, causing
    // "Callback invoked after it has been deleted" crashes.
    // In production (long-lived app), dispose() works fine since the
    // process doesn't exit immediately after.
    tempDir.deleteSync(recursive: true);
  });

  test('Info:ping responds via FFI', () async {
    final result = await client.info.ping();
    expect(result, isNotNull);
  });

  test('Info:version returns a string via FFI', () async {
    final version = await client.info.version();
    expect(version, isA<String>());
    expect(version, isNotEmpty);
  });

  test('Info:onboarding returns state via FFI', () async {
    final state = await client.info.onboarding();
    expect(state.hasWallet, false);
  });

  test('Network list returns networks via FFI', () async {
    final networks = await client.networks.list();
    expect(networks, isA<List<Network>>());
    expect(networks, isNotEmpty);
  });

  test('Wallet list is initially empty via FFI', () async {
    final wallets = await client.wallets.list();
    expect(wallets, isEmpty);
  });

  test('create and delete a wallet via FFI', () async {
    Wallet? createdWallet;
    await for (final event in client.wallets.create(
      name: 'FFI Test Wallet',
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
    expect(createdWallet!.name, 'FFI Test Wallet');
    expect(createdWallet.keys, hasLength(3));

    // Create an account
    final account = await client.accounts.create(
      name: 'FFI Test Account',
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
}
