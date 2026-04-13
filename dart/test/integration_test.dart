@TestOn('vm')
@Timeout(Duration(minutes: 5))
library;

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:libwallet/libwallet.dart';

/// Integration tests that start the Go test server and communicate over the
/// Unix socket. Requires the testserver binary to be built first:
///   cd .. && go build -o dart/testserver/testserver ./dart/testserver/
void main() {
  late Process server;
  late String socketPath;
  late LibwalletClient client;

  setUpAll(() async {
    final binPath = '${Directory.current.path}/testserver/testserver';
    if (!File(binPath).existsSync()) {
      fail('testserver binary not found at $binPath\n'
          'Build it first: cd .. && go build -o dart/testserver/testserver ./dart/testserver/');
    }

    server = await Process.start(binPath, []);

    // First line of stdout is the socket path
    final line = await server.stdout
        .transform(const SystemEncoding().decoder)
        .transform(const LineSplitter())
        .first;
    socketPath = line.trim();

    // Small delay for the listener to be fully ready
    await Future.delayed(const Duration(milliseconds: 200));

    client = await LibwalletClient.connect(socketPath);
  });

  tearDownAll(() async {
    client.dispose();
    server.kill(ProcessSignal.sigterm);
    await server.exitCode;
  });

  test('Info:ping responds', () async {
    final result = await client.info.ping();
    expect(result, isNotNull);
  });

  test('Info:version returns a string', () async {
    final version = await client.info.version();
    expect(version, isA<String>());
    expect(version, isNotEmpty);
  });

  test('Info:onboarding returns state', () async {
    final state = await client.info.onboarding();
    // Fresh database: no wallet yet
    expect(state.hasWallet, false);
  });

  test('Network list returns networks', () async {
    final networks = await client.networks.list();
    expect(networks, isA<List<Network>>());
    // Should have built-in networks
    expect(networks, isNotEmpty);
  });

  test('Wallet list is initially empty', () async {
    final wallets = await client.wallets.list();
    expect(wallets, isEmpty);
  });

  test('Account list is initially empty', () async {
    final accounts = await client.accounts.list();
    expect(accounts, isEmpty);
  });

  test('Contact list is initially empty', () async {
    final contacts = await client.contacts.list();
    expect(contacts, isEmpty);
  });

  test('create and delete a wallet with password-only keys', () async {
    // Create a password-only (unsafe) wallet for testing -- no remote key needed
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
          // TSS key generation progress
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

    // Onboarding should now show hasWallet
    final state = await client.info.onboarding();
    expect(state.hasWallet, true);

    // Create an account on this wallet
    final account = await client.accounts.create(
      name: 'Test Account',
      wallet: createdWallet.id,
      type: 'ethereum',
      index: 0,
    );
    expect(account.address, isNotEmpty);
    expect(account.type, 'ethereum');

    // Verify account shows in list
    final accounts = await client.accounts.list();
    expect(accounts, isNotEmpty);

    // Clean up: delete the wallet (cascades to accounts)
    await client.wallets.delete(createdWallet.id);
    final afterDelete = await client.wallets.list();
    expect(afterDelete, isEmpty);
  });

  test('raw request works', () async {
    final result = await client.rawRequest('Info:ping');
    expect(result, isNotNull);
  });
}
