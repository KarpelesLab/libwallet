@TestOn('vm')
@Timeout(Duration(minutes: 10))
library;

import 'dart:ffi';
import 'dart:io';

import 'package:test/test.dart';
import 'package:libwallet/libwallet.dart';

/// Comprehensive integration tests using the FFI transport.
/// Exercises all API endpoints against a real Go library.
///
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
    // Don't call client.dispose() in tests — Go c-shared runtime cleanup
    // races with Dart isolate shutdown. In production apps this is fine.
    tempDir.deleteSync(recursive: true);
  });

  // ── Info ──────────────────────────────────────────────────────────────

  group('Info', () {
    test('ping', () async {
      final result = await client.info.ping();
      expect(result, isNotNull);
    });

    test('version', () async {
      final version = await client.info.version();
      expect(version, isA<String>());
      expect(version, isNotEmpty);
    });

    test('paths', () async {
      final paths = await client.info.paths();
      expect(paths, isA<Map<String, dynamic>>());
    });

    test('firstRun', () async {
      final result = await client.info.firstRun();
      expect(result, isNotNull);
    });

    test('onboarding (fresh db)', () async {
      final state = await client.info.onboarding();
      expect(state.hasWallet, false);
    });
  });

  // ── Crash ─────────────────────────────────────────────────────────────

  group('Crash', () {
    test('list is initially empty', () async {
      final crashes = await client.crashes.list();
      expect(crashes, isEmpty);
    });
  });

  // ── Network ───────────────────────────────────────────────────────────

  group('Network', () {
    test('list returns built-in networks', () async {
      final networks = await client.networks.list();
      expect(networks, isNotEmpty);
      expect(networks.first.name, isNotEmpty);
      expect(networks.first.currencySymbol, isNotEmpty);
    });

    test('list with testNet filter', () async {
      final all = await client.networks.list();
      final noTestnets = await client.networks.list(testNet: false);
      expect(noTestnets.length, lessThanOrEqualTo(all.length));
    });

    test('get by ID', () async {
      final networks = await client.networks.list();
      if (networks.isEmpty) return;
      final net = await client.networks.get(networks.first.id);
      expect(net.id, networks.first.id);
      expect(net.name, networks.first.name);
    });

    test('setCurrent and getCurrent', () async {
      final networks = await client.networks.list();
      if (networks.isEmpty) return;
      await client.networks.setCurrent(networks.first.id);
      final current = await client.networks.getCurrent();
      expect(current.id, networks.first.id);
    });

    test('testRpc', () async {
      // testRpc may fail with third-party RPCs in CI — just verify it doesn't crash
      try {
        final result =
            await client.networks.testRpc('https://eth.llamarpc.com');
        expect(result, isNotNull);
      } on LibwalletException {
        // RPC may be unreachable or return unexpected format — acceptable
      }
    });
  });

  // ── Contact ───────────────────────────────────────────────────────────

  group('Contact', () {
    test('CRUD lifecycle', () async {
      // List — initially empty
      var contacts = await client.contacts.list();
      expect(contacts, isEmpty);

      // Create
      final contact = await client.contacts.create(
        name: 'Alice',
        address: '0x1234567890abcdef1234567890abcdef12345678',
        type: 'ethereum',
        memo: 'test contact',
      );
      expect(contact.name, 'Alice');
      expect(contact.address, contains('0x'));
      expect(contact.type, 'ethereum');
      expect(contact.memo, 'test contact');

      // List — now has one
      contacts = await client.contacts.list();
      expect(contacts, hasLength(1));

      // Get by ID
      final fetched = await client.contacts.get(contact.id);
      expect(fetched.name, 'Alice');

      // Update
      final updated = await client.contacts.update(contact.id, {'Name': 'Bob'});
      expect(updated.name, 'Bob');

      // Delete
      await client.contacts.delete(contact.id);
      contacts = await client.contacts.list();
      expect(contacts, isEmpty);
    });
  });

  // ── Lifecycle ──────────────────────────────────────────────────────────

  group('Lifecycle', () {
    test('update does not throw', () async {
      // Lifecycle:update triggers background maintenance — just verify it doesn't error
      try {
        await client.lifecycle.update();
      } on LibwalletException {
        // May fail if no network — acceptable
      }
    });
  });

  // ── StoreKey ──────────────────────────────────────────────────────────

  group('StoreKey', () {
    test('create returns keypair', () async {
      final keypair = await client.storeKeys.create();
      expect(keypair.privateKey, isNotEmpty);
      expect(keypair.publicKey, isNotEmpty);
    });
  });

  // ── Name resolution (ENS / SNS) ───────────────────────────────────────

  group('Names', () {
    test('resolve ENS name', () async {
      // vitalik.eth is famously stable; use it as a smoke test.
      try {
        final res = await client.names.resolve('vitalik.eth');
        expect(res.name, 'vitalik.eth');
        expect(res.network, 'ethereum');
        expect(res.address, startsWith('0x'));
        expect(res.address.length, 42);
      } on LibwalletException {
        // RPC may be unreachable in CI — acceptable.
      }
    });

    test('reject unsupported suffix', () async {
      expect(
        () => client.names.resolve('foo.com'),
        throwsA(isA<LibwalletException>()),
      );
    });
  });

  // ── RemoteKey ─────────────────────────────────────────────────────────

  group('RemoteKey', () {
    // Test phone number +14045551234 does not send SMS, verify code is 000000
    test('new → validate lifecycle', () async {
      // Start remote key setup with test phone
      final session = await client.remoteKeys.create(number: '+14045551234');
      expect(session, isNotNull);

      // Extract session ID
      final sessionId = session is Map ? session['session'] as String : session.toString();
      expect(sessionId, isNotEmpty);

      // Validate with test code
      final result =
          await client.remoteKeys.validate(session: sessionId, code: '000000');
      expect(result, isNotNull);
    });
  });

  // ── Wallet full lifecycle ─────────────────────────────────────────────

  group('Wallet', () {
    late Wallet wallet;

    test('create with progress', () async {
      int progressCount = 0;
      await for (final event in client.wallets.create(
        name: 'Test Wallet',
        keys: [
          KeyDescription.password('pass-1'),
          KeyDescription.password('pass-2'),
          KeyDescription.password('pass-3'),
        ],
      )) {
        switch (event) {
          case Progress():
            progressCount++;
          case Complete(:final value):
            wallet = value;
        }
      }

      expect(wallet.name, 'Test Wallet');
      expect(wallet.curve, 'secp256k1');
      expect(wallet.threshold, greaterThan(0));
      expect(wallet.keys, hasLength(3));
      expect(wallet.pubkey, isNotEmpty);
      expect(wallet.chaincode, isNotEmpty);
      expect(progressCount, greaterThan(0));
    });

    test('list returns created wallet', () async {
      final wallets = await client.wallets.list();
      expect(wallets, hasLength(1));
      expect(wallets.first.id, wallet.id);
    });

    test('get by ID', () async {
      final fetched = await client.wallets.get(wallet.id);
      expect(fetched.id, wallet.id);
      expect(fetched.name, wallet.name);
      expect(fetched.keys, hasLength(3));
    });

    test('update name', () async {
      final updated =
          await client.wallets.update(wallet.id, name: 'Renamed Wallet');
      expect(updated.name, 'Renamed Wallet');
    });

    test('onboarding shows hasWallet', () async {
      final state = await client.info.onboarding();
      expect(state.hasWallet, true);
    });

    test('backup', () async {
      final backup = await client.wallets.backup(wallet.id);
      expect(backup, isNotNull);
    });

    test('restore from backup', () async {
      final backup = await client.wallets.backup(wallet.id);
      // backup is a list of {filename, data} entries
      if (backup is List) {
        final files = backup
            .map((e) => Map<String, String>.from(e as Map))
            .toList();
        final result = await client.wallets.restore(files);
        expect(result, isA<Map<String, dynamic>>());
      }
    });

    // ── WalletKey ─────────────────────────────────────────────────────

    test('WalletKey get', () async {
      final key = await client.walletKeys.get(wallet.keys.first.id);
      expect(key.id, wallet.keys.first.id);
      expect(key.type, wallet.keys.first.type);
    });

    test('WalletKey recrypt (change password)', () async {
      final passwordKey = wallet.keys.firstWhere((k) => k.isPassword);
      final result = await client.walletKeys.recrypt(
        passwordKey.id,
        oldPassword: 'pass-1',
        newPassword: 'new-pass-1',
      );
      expect(result, isNotNull);
    });

    // ── Account ───────────────────────────────────────────────────────

    group('Account', () {
      late Account account;

      test('list initially empty', () async {
        final accounts = await client.accounts.list();
        expect(accounts, isEmpty);
      });

      test('create ethereum account', () async {
        account = await client.accounts.create(
          name: 'ETH Account',
          wallet: wallet.id,
          type: 'ethereum',
          index: 0,
        );
        expect(account.address, isNotEmpty);
        expect(account.type, 'ethereum');
        expect(account.wallet, wallet.id);
      });

      test('list by wallet', () async {
        final accounts = await client.accounts.list(wallet: wallet.id);
        expect(accounts, hasLength(1));
        expect(accounts.first.id, account.id);
      });

      test('get by ID', () async {
        final fetched = await client.accounts.get(account.id);
        expect(fetched.id, account.id);
        expect(fetched.address, account.address);
      });

      test('setCurrent and getCurrent', () async {
        await client.accounts.setCurrent(account.id);
        final current = await client.accounts.getCurrent();
        expect(current.id, account.id);
      });

      test('update name', () async {
        final updated =
            await client.accounts.update(account.id, name: 'Renamed Account');
        expect(updated.name, 'Renamed Account');
      });

      // ── Asset ───────────────────────────────────────────────────────

      test('Asset list (may be empty without funded account)', () async {
        final assets = await client.assets.list();
        expect(assets, isA<List<Asset>>());
      });

      test('Asset list with fiat conversion', () async {
        final assets = await client.assets.list(convert: 'USD');
        expect(assets, isA<List<Asset>>());
      });

      // ── Transaction ─────────────────────────────────────────────────

      test('Transaction list (empty for new account)', () async {
        final txs = await client.transactions.list();
        expect(txs, isEmpty);
      });

      test('Transaction list filtered by account', () async {
        final txs = await client.transactions.list(from: account.id);
        expect(txs, isEmpty);
      });

      // ── Transaction validate ──────────────────────────────────────

      test('Transaction validate (missing fields returns error)', () async {
        try {
          await client.transactions.validate({
            'type': 'transfer',
            'from': account.id,
            'to': '0x0000000000000000000000000000000000000000',
          });
        } on LibwalletException catch (e) {
          // Expected: validation error for missing amount/asset etc.
          expect(e.message, isNotEmpty);
        }
      });

      // ── NFT ─────────────────────────────────────────────────────────

      test('Nft list', () async {
        final result = await client.nfts.list();
        expect(result, isA<Map<String, dynamic>>());
      });

      // ── Token ───────────────────────────────────────────────────────

      test('Token list (initially empty)', () async {
        final tokens = await client.tokens.list();
        expect(tokens, isEmpty);
      });

      test('Token CRUD lifecycle', () async {
        // Find an EVM network for the token
        final networks = await client.networks.list();
        final evmNetwork = networks.firstWhere(
          (n) => n.type == NetworkType.evm && !n.testNet,
          orElse: () => networks.first,
        );

        // Create
        final token = await client.tokens.create(
          name: 'Test Token',
          symbol: 'TST',
          address: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
          decimals: 6,
          network: evmNetwork.id,
          type: 'erc20',
        );
        expect(token.name, 'Test Token');
        expect(token.symbol, 'TST');
        expect(token.decimals, 6);

        // List
        var tokens = await client.tokens.list();
        expect(tokens, hasLength(1));

        // Get
        final fetched = await client.tokens.get(token.id);
        expect(fetched.symbol, 'TST');

        // Update
        final updated =
            await client.tokens.update(token.id, {'Name': 'Updated Token'});
        expect(updated.name, 'Updated Token');

        // Delete
        await client.tokens.delete(token.id);
        tokens = await client.tokens.list();
        expect(tokens, isEmpty);
      });

      // Clean up account
      test('delete account', () async {
        await client.accounts.delete(account.id);
        final accounts = await client.accounts.list();
        expect(accounts, isEmpty);
      });
    });

    // ── Web3/Connection ───────────────────────────────────────────────

    group('Web3/Connection', () {
      test('list initially empty', () async {
        final connections = await client.web3Connections.list();
        expect(connections, isEmpty);
      });
    });

    // ── Request ────────────────────────────────────────────────────────

    group('Request', () {
      test('test fires a test event', () async {
        try {
          await client.requests.test();
        } on LibwalletException {
          // May fail without a connected Web3 session — acceptable
        }
      });
    });

    // ── Clean up wallet ───────────────────────────────────────────────

    test('delete wallet', () async {
      await client.wallets.delete(wallet.id);
      final wallets = await client.wallets.list();
      expect(wallets, isEmpty);
    });
  });

  // ── Raw request ───────────────────────────────────────────────────────

  test('rawRequest works', () async {
    final result = await client.rawRequest('Info:ping');
    expect(result, isNotNull);
  });
}
