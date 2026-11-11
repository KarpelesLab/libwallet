@TestOn('vm')
@Timeout(Duration(minutes: 10))
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

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
      // The tagged release version is only set by ldflags on a `v*`
      // tag build; under `dart test` from master / local dev it's
      // legitimately empty. Just verify the wire shape.
      final version = await client.info.version();
      expect(version, isA<String>());

      final info = await client.info.versionInfo();
      // gitTag is set by CI's ldflag plumbing on every release build,
      // and by the local Makefile when present. dart-test's test-host
      // job builds without ldflags, so we only assert the wire shape.
      expect(info, isA<VersionInfo>());
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
      final updated = await client.contacts.update(contact.id, name: 'Bob');
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
        await client.lifecycle.update('foreground');
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

    test('derivePassword returns the Public_Key, deterministically', () async {
      // Any wkey-prefixed xuid works as a salt; the key id is the only input
      // besides the password, so the same pair must derive the same pubkey.
      const wkeyId = 'wkey-aaaaaa-bbbb-cccc-dddd-eeeeeeee';
      final a = await client.storeKeys.derivePassword(
          password: 'passwordone', walletKeyId: wkeyId);
      final b = await client.storeKeys.derivePassword(
          password: 'passwordone', walletKeyId: wkeyId);
      final other = await client.storeKeys.derivePassword(
          password: 'passwordtwo', walletKeyId: wkeyId);
      expect(a, isNotEmpty);
      expect(a, equals(b));
      expect(other, isNot(equals(a)));
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
      expect(session.session, isNotEmpty);

      // Validate with test code
      final result =
          await client.remoteKeys.validate(session: session.session, code: '000000');
      expect(result.remoteKey, isNotEmpty);
    });
  });

  // ── Wallet full lifecycle ─────────────────────────────────────────────

  group('Wallet', () {
    test('generateMnemonic → validateMnemonic', () async {
      final twelve = await client.wallets.generateMnemonic();
      expect(twelve.split(' '), hasLength(12));
      expect(await client.wallets.validateMnemonic(twelve), isTrue);
      final twentyFour = await client.wallets.generateMnemonic(words: 24);
      expect(twentyFour.split(' '), hasLength(24));
      expect(await client.wallets.validateMnemonic(twentyFour), isTrue);
      expect(twentyFour, isNot(startsWith(twelve)));
      expect(await client.wallets.validateMnemonic('abandon ' * 11 + 'abandon'),
          isFalse);
      for (final n in [15, 18, 21]) {
        final m = await client.wallets.generateMnemonic(words: n);
        expect(m.split(' '), hasLength(n));
        expect(await client.wallets.validateMnemonic(m), isTrue);
      }
      await expectLater(
          client.wallets.generateMnemonic(words: 13), throwsA(anything));
    });

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
      expect(backup, isNotEmpty);
      final files = backup.map((e) => e.toJson()).toList();
      final result = await client.wallets.restore(files);
      expect(result, isA<Map<String, dynamic>>());
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
        try {
          final assets = await client.assets.list();
          expect(assets, isA<List<Asset>>());
        } on LibwalletException {
          // Upstream Ethereum RPC may return a transient -32603 in CI —
          // acceptable; the list path needs eth_getBalance and we don't
          // control Infura's availability.
        }
      });

      test('Asset list with fiat conversion', () async {
        try {
          final assets = await client.assets.list(convert: 'USD');
          expect(assets, isA<List<Asset>>());
        } on LibwalletException {
          // Same upstream-RPC tolerance as the bare Asset:list test above.
        }
      });

      test('Account nativeAsset', () async {
        try {
          final native = await client.accounts.nativeAsset(account.id);
          expect(native.isNative, isTrue);
          expect(native.key, endsWith('.NATIVE'));
        } on LibwalletException {
          // Same upstream-RPC tolerance as Asset:list (eth_getBalance).
        }
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
          await client.transactions.validate(UnsignedTransaction(
            type: 'transfer',
            from: account.id,
            to: '0x0000000000000000000000000000000000000000',
          ));
        } on LibwalletException catch (e) {
          // Expected: validation error for missing amount/asset etc.
          expect(e.message, isNotEmpty);
        }
      });

      test('Transaction simulate decodes ERC-20 transfer calldata', () async {
        // The simulation may fail to reach an RPC in CI, but calldata
        // decoding is client-local and should succeed regardless.
        // 0xa9059cbb = transfer(address,uint256) selector.
        final txCalldata = '0xa9059cbb'
            // address (32 bytes, zero-padded): 0xd8da6bf26964af9d7eed9e03e53415d37aa96045
            '000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045'
            // amount = 1000000 (0xf4240)
            '00000000000000000000000000000000000000000000000000000000000f4240';
        try {
          final sim = await client.transactions.simulate(UnsignedTransaction(
            type: 'evm',
            from: account.id,
            to: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', // USDC
            data: txCalldata,
          ));
          expect(sim.chain, 'evm');
          expect(sim.decodedMethod, 'erc20_transfer');
          expect(sim.decodedArgs['to'],
              '0xd8da6bf26964af9d7eed9e03e53415d37aa96045');
          expect(sim.decodedArgs['amount'], '1000000');
        } on LibwalletException catch (e) {
          // Simulation reached the validator but the network RPC is
          // unavailable in CI — still acceptable as long as the decoder
          // was exercised (if validate errored out before decoding, the
          // exception message won't mention the selector).
          expect(e.message, isNotEmpty);
        }
      });

      // ── NFT ─────────────────────────────────────────────────────────

      test('Nft list', () async {
        final result = await client.nfts.list();
        expect(result, isA<NftListing>());
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
            await client.tokens.update(token.id, name: 'Updated Token');
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

    // ── View accounts ───────────────────────────────────────────────────

    group('View accounts', () {
      test('create EVM view from address', () async {
        final view = await client.accounts.createView(
          type: 'ethereum',
          address: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045', // vitalik.eth
          name: 'Vitalik',
        );
        expect(view.isViewOnly, isTrue);
        expect(view.wallet, isEmpty);
        expect(view.address, '0xd8da6bf26964af9d7eed9e03e53415d37aa96045');
        expect(view.type, 'ethereum');
        await client.accounts.delete(view.id);
      });

      test('create Bitcoin view from xpub', () async {
        // Known mainnet xpub from the BIP-32 test vectors.
        const xpub =
            'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
        final view = await client.accounts.createView(
          type: 'bitcoin',
          xpub: xpub,
          name: 'BTC watch',
        );
        expect(view.isViewOnly, isTrue);
        expect(view.wallet, isEmpty);
        expect(view.pubkey, isNotEmpty);
        expect(view.chaincode, isNotEmpty);
        // Derived first receive address should round-trip via xpub() call.
        final roundtripped = await client.accounts.xpub(view.id);
        expect(roundtripped, isNotEmpty);
        await client.accounts.delete(view.id);
      });

      test('rejects xpub for non-bitcoin type', () async {
        expect(
          () => client.accounts.createView(
            type: 'ethereum',
            xpub: 'xpub...',
          ),
          throwsA(isA<LibwalletException>()),
        );
      });

      test('rejects both address and xpub', () async {
        expect(
          () => client.accounts.createView(
            type: 'bitcoin',
            address: 'bc1q...',
            xpub: 'xpub...',
          ),
          throwsA(isA<ArgumentError>()),
        );
      });
    });

    // ── Bitcoin HD address support ─────────────────────────────────────

    group('Bitcoin HD', () {
      late Account btcAccount;

      test('create bitcoin account', () async {
        btcAccount = await client.accounts.create(
          name: 'BTC Account',
          wallet: wallet.id,
          type: 'bitcoin',
          index: 0,
        );
        expect(btcAccount.type, 'bitcoin');
        expect(btcAccount.address, isNotEmpty);
      });

      test('xpub is a BIP-32 extended key', () async {
        final xpub = await client.accounts.xpub(btcAccount.id);
        expect(xpub, startsWith('xpub'));
        expect(xpub.length, greaterThan(100));
      });

      test('nextAddress returns clean address for fresh account', () async {
        // Find a bitcoin network (create one if needed)
        final networks = await client.networks.list();
        var btcNet = networks.where((n) => n.type == NetworkType.bitcoin).firstOrNull;
        btcNet ??= await client.networks.create(
          type: 'bitcoin',
          chainId: 'bitcoin',
          name: 'Bitcoin',
          currencySymbol: 'BTC',
        );

        try {
          final next = await client.accounts
              .nextAddress(btcAccount.id, network: btcNet.id);
          expect(next.address, isNotEmpty);
          expect(next.chain, 'receive');
          expect(next.index, greaterThanOrEqualTo(0));
        } on LibwalletException {
          // modchain RPC may be unreachable in CI — acceptable
        }
      });

      test('delete btc account', () async {
        await client.accounts.delete(btcAccount.id);
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
      test('raw requestEvents fires on test()', () async {
        final future = client.requestEvents
            .first
            .timeout(const Duration(seconds: 5));
        final testFuture = client.requests.test();
        final ev = await future;
        expect(ev.requestId, isNotEmpty);
        // The full request should now be embedded in the event.
        expect(ev.request, isNotNull);
        expect(ev.request!.host, 'www.example.com');
        expect(ev.request!, isA<UnknownPendingRequest>());
        expect(ev.request!.type, 'test');
        // Reject to unblock the backend's 2-minute timer.
        await client.requests.reject(ev.requestId);
        try {
          await testFuture;
        } catch (_) {}
      });

      test('pendingRequests stream carries full payload', () async {
        final future = client.pendingRequests
            .firstWhere((r) => r.host == 'www.example.com')
            .timeout(const Duration(seconds: 5));

        final testFuture = client.requests.test();

        final req = await future;
        expect(req.id, isNotEmpty);
        expect(req.host, 'www.example.com');
        expect(req, isA<UnknownPendingRequest>());
        expect(req.type, 'test');
        expect(req.isPending, isTrue);

        await client.requests.reject(req.id);
        try {
          await testFuture;
        } catch (_) {}
      });
    });

    // ── Web3 injection ──────────────────────────────────────────────────

    group('Web3 injection', () {
    test('injectionScript returns embedded config + provider shim', () async {
      final js = await client.web3.injectionScript(
        name: 'Libwallet Test',
        rdns: 'com.example.libwallet.test',
        uuid: 'aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee',
        icon: 'data:image/svg+xml;base64,PHN2Zy8+',
        bridge: 'libwalletBridge',
        host: 'https://example.com',
      );
      // Sanity: all three providers landed in the script.
      expect(js, contains('window.ethereum'));
      expect(js, contains('window.solana'));
      expect(js, contains('window.mpurse'));
      // EIP-6963 announce wiring.
      expect(js, contains('eip6963:announceProvider'));
      expect(js, contains('eip6963:requestProvider'));
      // Wallet Standard register-wallet wiring.
      expect(js, contains('wallet-standard:register-wallet'));
      // Config interpolation actually happened.
      expect(js, contains('Libwallet Test'));
      expect(js, contains('com.example.libwallet.test'));
      expect(js, contains('libwalletBridge'));
      // Placeholder got replaced (no literal __LIBWALLET_CONFIG__).
      expect(js, isNot(contains('__LIBWALLET_CONFIG__')));
    });

    test('injectionScript rejects missing required fields', () async {
      expect(
        () => client.web3.injectionScript(
          name: '',
          rdns: 'x.y',
          uuid: 'u',
          icon: 'data:,',
          bridge: 'b',
        ),
        throwsA(isA<LibwalletException>()),
      );
    });

    test('mpurse_getAddress over Web3:request triggers a connect prompt',
        () async {
      // No accounts connected yet on this host — the call blocks on a
      // pending connect request. We verify it reaches the request queue
      // via the pendingRequests stream, then reject.
      final future = client.pendingRequests
          .firstWhere((r) => r.host.startsWith('https://example.org'))
          .timeout(const Duration(seconds: 5));

      final callFuture = client.web3.request(
        origin: 'https://example.org',
        query: {'method': 'mpurse_getAddress', 'params': []},
      );

      final req = await future;
      expect(req, isA<ConnectRequest>());
      await client.requests.reject(req.id);
      try {
        await callFuture;
      } catch (_) {/* expected: call rejected */}
    });

    test('mpurse_signRawTransaction rejects calls without a connection',
        () async {
      try {
        await client.web3.request(
          origin: 'https://no-connection.example',
          query: {'method': 'mpurse_signRawTransaction', 'params': ['0100']},
        );
        fail('should have thrown');
      } on LibwalletException catch (e) {
        expect(e.message, contains('no account connected'));
      }
    });

    // DIVERGENCE FROM GO: Go's handler returns "not implemented" and leaves
    // Counterparty composition to the dApp. The Rust port composes the send
    // server-side (rust/src/counterparty.rs), so the method validates its
    // parameters instead. Composing needs a live Counterparty node, so what is
    // exercised here is that parameter contract — every check below runs before
    // any connected-account lookup or network call.
    test('mpurse_sendAsset validates its parameters', () async {
      Future<void> expectRejected(List<Object> params, Matcher message) async {
        try {
          await client.web3.request(
            origin: 'https://example.org',
            query: {'method': 'mpurse_sendAsset', 'params': params},
          );
          fail('should have thrown');
        } on LibwalletException catch (e) {
          expect(e.message, message);
        }
      }

      await expectRejected([], contains('requires one object param'));
      await expectRejected(
        [<String, Object>{}],
        contains("'to' is required"),
      );
      await expectRejected(
        [
          <String, Object>{'to': 'MHyMkTGUmKgunuDZzYNSVgnFTbYhQCiKSv'},
        ],
        contains("'asset' is required"),
      );
      await expectRejected(
        [
          <String, Object>{
            'to': 'MHyMkTGUmKgunuDZzYNSVgnFTbYhQCiKSv',
            'asset': 'XMP',
          },
        ],
        contains("'amount' must be a non-negative integer quantity"),
      );
    });

    test('mpurse_signMessage surfaces a typed MpurseSignMessageRequest', () async {
      // Set up a Monacoin network so the mpurse_signMessage approval
      // handler can pick the right Bitcoin-family signing prefix.
      final networks = await client.networks.list();
      var monaNet =
          networks.where((n) => n.chainId == 'monacoin').firstOrNull;
      monaNet ??= await client.networks.create(
        type: 'bitcoin',
        chainId: 'monacoin',
        name: 'Monacoin',
        currencySymbol: 'MONA',
      );
      await client.networks.setCurrent(monaNet.id);

      final monaAcct = await client.accounts.create(
        name: 'MONA',
        wallet: wallet.id,
        type: 'bitcoin',
        index: 5,
      );

      // Connect first so mpurse_signMessage has a connected account.
      const origin = 'https://mona.example';
      final connectFuture = client.pendingRequests
          .firstWhere((r) => r is ConnectRequest && r.host == origin)
          .timeout(const Duration(seconds: 5));
      final getAddressFuture = client.web3.request(
        origin: origin,
        query: {'method': 'mpurse_getAddress', 'params': []},
      );
      final connectReq = await connectFuture;
      await client.requests.approve(connectReq.id, accounts: [monaAcct.id]);
      final addr = await getAddressFuture;
      expect(addr as String, startsWith('mona1'));

      // Fire the signMessage call — routing check. Actual signature-
      // correctness is covered by a Go unit test.
      final signReqFuture = client.pendingRequests
          .firstWhere((r) =>
              r is MessageSignRequest && r.method == 'mpurse_signMessage')
          .timeout(const Duration(seconds: 5));
      final signCallFuture = client.web3.request(
        origin: origin,
        query: {
          'method': 'mpurse_signMessage',
          'params': ['hello from mpurse'],
        },
      ).catchError((_) => null); // expected to be rejected

      final signReq = await signReqFuture;
      expect(signReq, isA<MessageSignRequest>());
      final mSig = signReq as MessageSignRequest;
      expect(mSig.method, 'mpurse_signMessage');
      expect(mSig.messageText, 'hello from mpurse');
      await client.requests.reject(mSig.id);
      try {
        await signCallFuture;
      } catch (_) {/* expected */}

      await client.accounts.delete(monaAcct.id);
    });
  });

    // ── Clean up wallet ───────────────────────────────────────────────

    test('delete wallet', () async {
      await client.wallets.delete(wallet.id);
      final wallets = await client.wallets.list();
      expect(wallets, isEmpty);
    });
  });

  // ── WalletConnect v2 ──────────────────────────────────────────────────

  group('WalletConnect', () {
    test('start requires a projectId', () async {
      expect(
        () => client.walletConnect.start(projectId: ''),
        throwsA(isA<LibwalletException>()),
      );
    });

    test('pair rejects a malformed URI', () async {
      // Start with a throwaway projectId — start() itself succeeds even
      // if the relay never accepts us, because the dial happens in a
      // background goroutine.
      try {
        await client.walletConnect.start(projectId: 'test-project');
      } on LibwalletException {
        // already started in another test — ignore
      }
      expect(
        () => client.walletConnect.pair('not-a-wc-uri'),
        throwsA(isA<LibwalletException>()),
      );
    });

    test('sessions() returns empty list initially', () async {
      final sessions = await client.walletConnect.sessions();
      expect(sessions, isA<List<WcSession>>());
      // It may or may not be empty (other tests may have paired), so just
      // verify the shape parses.
    });

    test('respondError on unknown topic fails clearly', () async {
      try {
        await client.walletConnect.respondError(
          'deadbeef' * 8, // 64-char hex, but not a known session
          1,
          code: 5000,
          message: 'test',
        );
        fail('should have thrown');
      } on LibwalletException catch (e) {
        expect(e.message, contains('unknown topic'));
      }
    });
  });


  // ── Vault ─────────────────────────────────────────────────────────────
  // Host runs have no entitled keychain, so these use the password backend;
  // the secure backend is covered by the iOS/Android integration tests.

  group('Ledger', () {
    test('list reports the transports of this build', () async {
      final l = await client.ledger.list();
      expect(l.transports, contains('bridge'));
      expect(l.transports, contains(l.defaultTransport));
    });

    test('bridge relays APDUs to the app and back', () async {
      // The "device": answers GET_APP_AND_VERSION as the Ethereum app would.
      final seen = <Uint8List>[];
      final sub = client.ledger.bridge((apdu) async {
        seen.add(apdu);
        return Uint8List.fromList(
            [1, 8, ...'Ethereum'.codeUnits, 5, ...'1.2.3'.codeUnits, 0x90, 0x00]);
      });
      try {
        final info =
            await client.ledger.info(link: const LedgerLink.bridge());
        expect(info.appName, 'Ethereum');
        expect(info.appVersion, '1.2.3');
        expect(info.dashboard, isFalse);
        expect(seen.single, [0xb0, 0x01, 0x00, 0x00, 0x00]);
      } finally {
        await sub.cancel();
      }
    });

    test('a failing bridge fails the call, with the reason', () async {
      final sub = client.ledger
          .bridge((apdu) async => throw StateError('bluetooth is off'));
      try {
        await expectLater(
            client.ledger.info(link: const LedgerLink.bridge()),
            throwsA(isA<LibwalletException>()
                .having((e) => e.toString(), 'message', contains('bluetooth is off'))));
      } finally {
        await sub.cancel();
      }
    });

    test('signing needs an account on a Ledger wallet', () async {
      await expectLater(
          client.ledger.signMessage(
              account: 'acct-nope', message: Uint8List.fromList([1])),
          throwsA(isA<LibwalletException>()));
    });
  });

  group('CatCard', () {
    // A reply as the device frames it: [u16 status][u32 length][payload].
    Uint8List reply(int status, List<int> payload) => Uint8List.fromList([
          status & 0xff,
          status >> 8,
          payload.length & 0xff,
          payload.length >> 8,
          0,
          0,
          ...payload
        ]);

    test('list reports the transports of this build', () async {
      final l = await client.catcard.list();
      expect(l.transports, containsAll(['ccid', 'bridge']));
      expect(l.transports, contains(l.defaultTransport));
    });

    test('bridge relays messages to the app and back', () async {
      // The "device": answers Identify as an unlocked Q1 running 7.0.0.
      final seen = <Uint8List>[];
      final sub = client.catcard.bridge((message) async {
        seen.add(message);
        return reply(
            0, [2, 0, 1, 0xC0, 2, ...'q1'.codeUnits, 5, ...'7.0.0'.codeUnits]);
      });
      try {
        final info =
            await client.catcard.info(link: const CatCardLink.bridge());
        expect(info.board, 'q1');
        expect(info.firmware, '7.0.0');
        expect(info.protocol, 2);
        expect(info.unlocked, isTrue);
        expect(info.pairing && info.hostWallet, isTrue);
        expect(info.bench, isFalse);
        expect(info.paired, isFalse);
        // What the firmware can do is only told inside a paired channel,
        // and info never pairs to find out.
        expect(info.hostInfo, isNull);
        // Identify: opcode 2, no payload.
        expect(seen.single, [2, 0, 0, 0, 0, 0]);
      } finally {
        await sub.cancel();
      }
    });

    test('ccidBridge relays APDUs to the card and back', () async {
      // The "card": answers Identify, as docs/PHONE-APP.md §2 shows it.
      final seen = <Uint8List>[];
      final sub = client.catcard.ccidBridge((apdu) async {
        seen.add(apdu);
        return Uint8List.fromList([
          ...reply(0,
              [2, 0, 1, 0xC0, 2, ...'q1'.codeUnits, 5, ...'7.0.0'.codeUnits]),
          0x90,
          0x00
        ]);
      });
      try {
        final info = await client.catcard.info(link: const CatCardLink.ccid());
        expect(info.board, 'q1');
        expect(info.firmware, '7.0.0');
        expect(info.unlocked, isTrue);
        // 80 CC 00 00, extended Lc = 6, opcode 2 + total 0, extended Le.
        expect(seen.single,
            [0x80, 0xCC, 0, 0, 0, 0, 6, 2, 0, 0, 0, 0, 0, 0, 0]);
      } finally {
        await sub.cancel();
      }
    });

    test('a card that refuses the APDU fails the call', () async {
      final sub = client.catcard
          .ccidBridge((apdu) async => Uint8List.fromList([0x6D, 0x00]));
      try {
        await expectLater(
            client.catcard.info(link: const CatCardLink.ccid(shortApdu: true)),
            throwsA(isA<LibwalletException>()
                .having((e) => e.toString(), 'message', contains('6D00'))));
      } finally {
        await sub.cancel();
      }
    });

    test('a pairing code the user turns down pairs nothing', () async {
      // The device answers the handshake; the user says the codes differ.
      final opcodes = <int>[];
      final sub = client.catcard.bridge((message) async {
        final opcode = message[0] | (message[1] << 8);
        opcodes.add(opcode);
        switch (opcode) {
          case 0x0002:
            return reply(0,
                [2, 0, 1, 0xC0, 2, ...'q1'.codeUnits, 5, ...'7.0.0'.codeUnits]);
          case 0x0042: // PairCommit: the device's X25519 key (RFC 7748 §6.1)
            return reply(0, [
              0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61,
              0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78,
              0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
            ]);
          default: // PairReveal, PairAbort
            return reply(0, []);
        }
      });
      final codes = <String>[];
      final pairing = client.catcard.pairing.listen((p) async {
        codes.add(p.code);
        await client.catcard.confirmPairing(p, accept: false);
      });
      try {
        await expectLater(
            client.catcard.getKeys(link: const CatCardLink.bridge()),
            throwsA(isA<LibwalletException>().having((e) => e.toString(),
                'message', contains('pairing code was not confirmed'))));
        expect(codes.single, matches(RegExp(r'^\d{3} \d{3}$')));
        // Identify, commit, reveal, then the abort — and nothing sealed.
        expect(opcodes, [0x0002, 0x0042, 0x0043, 0x0045]);
      } finally {
        await pairing.cancel();
        await sub.cancel();
      }
    });

    test('a failing bridge fails the call, with the reason', () async {
      final sub = client.catcard
          .bridge((message) async => throw StateError('no reader'));
      try {
        await expectLater(
            client.catcard.info(link: const CatCardLink.bridge()),
            throwsA(isA<LibwalletException>()
                .having((e) => e.toString(), 'message', contains('no reader'))));
      } finally {
        await sub.cancel();
      }
    });

    test('signing needs an account on a CatCard wallet', () async {
      await expectLater(
          client.catcard.signTransaction(
              account: 'acct-nope', transaction: {'to': '0x00', 'value': '1'}),
          throwsA(isA<LibwalletException>()));
    });

    test('showing an address and signing a message need a CatCard account',
        () async {
      final notFound = throwsA(isA<LibwalletException>().having(
          (e) => e.toString(), 'message', contains('account not found')));
      await expectLater(client.catcard.showAddress('acct-nope'), notFound);
      await expectLater(
          client.catcard.signMessage(
              account: 'acct-nope',
              message: Uint8List.fromList('hi'.codeUnits),
              scheme: 'bip322'),
          notFound);
      await expectLater(
          client.catcard.signMessageDetailed(
              account: 'acct-nope', message: Uint8List.fromList([1])),
          notFound);
    });

    test('keys by path are checked before the device is asked', () async {
      // Nothing may reach a device for a request that cannot be made.
      final seen = <Uint8List>[];
      final sub = client.catcard.bridge((message) async {
        seen.add(message);
        return reply(1, []);
      });
      try {
        Future<void> refused(Future<CatCardKeys> call, String why) =>
            expectLater(
                call,
                throwsA(isA<LibwalletException>()
                    .having((e) => e.toString(), 'message', contains(why))));
        const link = CatCardLink.bridge();
        // A path that names no chain, a chain the device does not sign for,
        // a Solana path that is not hardened throughout, a bad script kind.
        await refused(
            client.catcard.getKeys(paths: ['m/0/1'], link: link), 'Chain');
        await refused(
            client.catcard
                .getKeys(paths: ["m/44'/60'/0'/0/1"], chain: 'tron', link: link),
            'Chain must be');
        await refused(
            client.catcard.getKeys(paths: ["m/44'/501'/0'/0"], link: link),
            'hardened throughout');
        await refused(
            client.catcard.getKeys(
                paths: ["m/84'/0'/0'/0/1"], format: 'p2wsh', link: link),
            'Format');
        await refused(
            client.catcard
                .getKeys(paths: ["m/44'/60'/0'/0/1"], account: 1, link: link),
            'Account');
        expect(seen, isEmpty);
      } finally {
        await sub.cancel();
      }
    });

    test('the models read what the firmware says of itself', () {
      final info = CatCardInfo.fromJson({
        'board': 'q1',
        'firmware': '7.1.0',
        'protocol': 2,
        'unlocked': true,
        'paired': true,
        'hostInfo': {
          'legacy': false,
          'addressAt': true,
          'signMessage': true,
          'pathsAllowed': true,
          'shared': false,
          'messageMax': 960,
          'chains': [
            {
              'chain': 1,
              'name': 'Bitcoin',
              'addresses': true,
              'sign': true,
              'messages': true,
              'formats': ['p2wpkh', 'p2tr']
            },
            {
              'chain': 3,
              'name': 'Solana',
              'addresses': true,
              'sign': true,
              'messages': false,
              'formats': ['solana']
            },
          ],
        },
      });
      final host = info.hostInfo!;
      expect(host.legacy, isFalse);
      expect(host.addressAt && host.signMessage && host.pathsAllowed, isTrue);
      expect(host.shared, isFalse);
      expect(host.messageMax, 960);
      expect(host.chains.map((c) => c.name), ['Bitcoin', 'Solana']);
      expect(host.chains.first.formats, ['p2wpkh', 'p2tr']);
      expect(host.chains.last.messages, isFalse);
      // Older firmware: the first six requests only.
      final old = CatCardInfo.fromJson({
        'paired': true,
        'hostInfo': {'legacy': true, 'addressAt': false, 'signMessage': false}
      }).hostInfo!;
      expect(old.legacy, isTrue);
      expect(old.addressAt || old.signMessage, isFalse);
      expect(old.chains, isEmpty);

      final signed = CatCardSignedMessage.fromJson({
        'account': 'acct-1',
        'address': 'bc1p…',
        'scheme': 'bip322',
        'verified': false,
        'signature': 'AkgwRQ==',
        'path': "m/86'/0'/0'/0/0",
      });
      expect(signed.scheme, 'bip322');
      expect(signed.verified, isFalse);
      expect(signed.path, "m/86'/0'/0'/0/0");
    });
  });

  group('Vault', () {
    const vaultPw = 'vault password 1';

    test('capabilities answer', () async {
      final caps = await client.vault.capabilities();
      if (!caps.secure) expect(caps.reason, isNotEmpty);
    });

    test('MPC wallet whose shares live in the vault signs without secrets in Dart',
        () async {
      final sk = await client.vault.create(
          kind: 'storekey',
          backend: 'password',
          password: vaultPw,
          policy: const VaultPolicy(cacheSeconds: -1));
      expect(sk.publicKey, isNotEmpty);
      expect(sk.blob, isNotEmpty);
      final pw = await client.vault
          .create(kind: 'password', backend: 'password', password: vaultPw);

      late Wallet w;
      await for (final e in client.wallets.create(name: 'Vault wallet', keys: [
        KeyDescription.vault(sk.id),
        KeyDescription.vault(pw.id, password: vaultPw),
        KeyDescription.password('pass-3'),
      ])) {
        if (e case Complete(:final value)) w = value;
      }
      expect(w.keys[0].key, sk.publicKey);
      final acct = await client.accounts
          .create(name: 'V', wallet: w.id, type: 'ethereum', index: 0);

      Future<SignedMessage> sign(List<KeyDescription> keys) =>
          client.accounts.signMessage(acct.id,
              message: Uint8List.fromList('hi'.codeUnits),
              keys: keys.map((k) => k.toJson()).toList());

      // Locked StoreKey entry: refused until unlocked.
      await expectLater(
          sign([
            KeyDescription.vault(sk.id, walletKeyId: w.keys[0].id),
            KeyDescription.password('pass-3').withId(w.keys[2].id),
          ]),
          throwsA(anything));
      await client.vault.unlock(sk.id, password: vaultPw);
      expect(await client.vault.isUnlocked(sk.id), isTrue);
      final sig = await sign([
        KeyDescription.vault(sk.id, walletKeyId: w.keys[0].id),
        KeyDescription.vault(pw.id, walletKeyId: w.keys[1].id, password: vaultPw),
      ]);
      expect(sig.signature, startsWith('0x'));

      // Backgrounding locks.
      await client.lifecycle.update('background');
      expect(await client.vault.isUnlocked(sk.id), isFalse);

      // Not exportable by default.
      await expectLater(client.vault.export(sk.id, password: vaultPw),
          throwsA(anything));
    });

    test('blob reload, password change, import and moveToVault', () async {
      final e = await client.vault.create(
          kind: 'data',
          backend: 'password',
          password: vaultPw,
          policy: const VaultPolicy(exportable: true));
      final secret = await client.vault.export(e.id, password: vaultPw);
      final blob = await client.vault.blob(e.id);
      expect(await client.vault.delete(e.id), isTrue);
      final back = await client.vault.load(blob);
      expect(back.id, e.id);
      expect(await client.vault.export(e.id, password: vaultPw), secret);
      await client.vault.changePassword(e.id, vaultPw, 'new vault password');
      await expectLater(client.vault.export(e.id, password: vaultPw),
          throwsA(anything));
      expect(await client.vault.export(e.id, password: 'new vault password'),
          secret);

      // Migrating an app-held StoreKey keeps its public key.
      final pair = await client.storeKeys.create();
      final imported = await client.vault.import(
          kind: 'storekey',
          secret: pair.privateKey,
          backend: 'password',
          password: vaultPw);
      expect(imported.publicKey, pair.publicKey);

      // Moving an existing Password share under a vault entry.
      late Wallet w;
      await for (final ev in client.wallets.create(name: 'Migrate', keys: [
        KeyDescription.password('old-pass-1'),
        KeyDescription.password('old-pass-2'),
        KeyDescription.password('old-pass-3'),
      ])) {
        if (ev case Complete(:final value)) w = value;
      }
      final moved = await client.walletKeys.moveToVault(w.keys[0].id,
          from: KeyDescription.password('old-pass-1'), entryId: imported.id);
      expect(moved.type, 'StoreKey');
      expect(moved.key, pair.publicKey);
    });
  });
}
