import 'package:test/test.dart';
import 'package:libwallet/libwallet.dart';

void main() {
  group('Wallet', () {
    test('fromJson parses wallet', () {
      final w = Wallet.fromJson({
        'Id': 'wlt-abc123',
        'Name': 'My Wallet',
        'Curve': 'secp256k1',
        'Threshold': 1,
        'Gen': 0,
        'Pubkey': 'base64pubkey',
        'Chaincode': 'base64cc',
        'Created': '2024-01-01T00:00:00Z',
        'Modified': '2024-01-01T00:00:00Z',
        'Keys': [
          {
            'Id': 'wkey-1',
            'Wallet': 'wlt-abc123',
            'Type': 'StoreKey',
            'Key': 'pubkey1',
            'Gen': 0,
          },
          {
            'Id': 'wkey-2',
            'Wallet': 'wlt-abc123',
            'Type': 'Password',
            'Key': '',
            'Gen': 0,
          },
        ],
      });
      expect(w.id, 'wlt-abc123');
      expect(w.name, 'My Wallet');
      expect(w.curve, 'secp256k1');
      expect(w.keys, hasLength(2));
      expect(w.keys[0].isStoreKey, true);
      expect(w.keys[1].isPassword, true);
      expect(w.isUnsafe, false);
    });

    test('isUnsafe when all keys are Password', () {
      final w = Wallet.fromJson({
        'Id': 'wlt-abc',
        'Name': 'Unsafe',
        'Curve': 'secp256k1',
        'Threshold': 1,
        'Gen': 0,
        'Pubkey': '',
        'Chaincode': '',
        'Created': '2024-01-01T00:00:00Z',
        'Modified': '2024-01-01T00:00:00Z',
        'Keys': [
          {'Id': 'wkey-1', 'Wallet': 'wlt-abc', 'Type': 'Password', 'Key': '', 'Gen': 0},
          {'Id': 'wkey-2', 'Wallet': 'wlt-abc', 'Type': 'Password', 'Key': '', 'Gen': 0},
          {'Id': 'wkey-3', 'Wallet': 'wlt-abc', 'Type': 'Password', 'Key': '', 'Gen': 0},
        ],
      });
      expect(w.isUnsafe, true);
    });
  });

  group('Account', () {
    test('fromJson parses account', () {
      final a = Account.fromJson({
        'Id': 'acct-xyz',
        'Wallet': 'wlt-abc',
        'Name': 'Main',
        'Index': 0,
        'Type': 'ethereum',
        'Path': 'm/44/60/0/0',
        'Address': '0x1234567890abcdef',
        'URI': 'ethereum:0x1234567890abcdef',
        'Pubkey': 'pubkey',
        'Chaincode': 'cc',
        'Created': '2024-01-01T00:00:00Z',
        'Updated': '2024-01-01T00:00:00Z',
      });
      expect(a.id, 'acct-xyz');
      expect(a.type, 'ethereum');
      expect(a.address, '0x1234567890abcdef');
    });
  });

  group('Network', () {
    test('fromJson parses network', () {
      final n = Network.fromJson({
        'Id': 'net-eth',
        'Type': 'evm',
        'ChainId': '1',
        'Name': 'Ethereum',
        'RPC': 'https://eth.example.com',
        'CurrencySymbol': 'ETH',
        'CurrencyDecimals': 18,
        'BlockExplorer': 'https://etherscan.io',
        'TestNet': false,
        'Priority': 100,
        'Created': '2024-01-01T00:00:00Z',
        'Updated': '2024-01-01T00:00:00Z',
      });
      expect(n.type, NetworkType.evm);
      expect(n.currencySymbol, 'ETH');
      expect(n.testNet, false);
    });

    test('NetworkType.fromString handles unknown', () {
      expect(NetworkType.fromString('evm'), NetworkType.evm);
      expect(NetworkType.fromString('bitcoin'), NetworkType.bitcoin);
      expect(NetworkType.fromString('solana'), NetworkType.solana);
      expect(NetworkType.fromString('foo'), NetworkType.unknown);
    });

    Network mk(NetworkType t, String chainId, String resolved) => Network(
          id: 'net-x',
          type: t,
          chainId: chainId,
          name: '',
          rpc: '',
          currencySymbol: '',
          currencyDecimals: 18,
          blockExplorer: 'auto',
          resolvedBlockExplorer: resolved,
          testNet: false,
          priority: 0,
          created: DateTime.parse('2024-01-01T00:00:00Z'),
          updated: DateTime.parse('2024-01-01T00:00:00Z'),
        );

    group('addressUrl/transactionUrl', () {
      test('EVM mainnet', () {
        final n = mk(NetworkType.evm, '1', 'https://etherscan.io');
        expect(n.addressUrl('0xabc'), 'https://etherscan.io/address/0xabc');
        expect(n.transactionUrl('0xdead'), 'https://etherscan.io/tx/0xdead');
      });

      test('Solana mainnet (no cluster suffix)', () {
        final n = mk(NetworkType.solana, 'mainnet', 'https://explorer.solana.com');
        expect(n.addressUrl('Aaa'), 'https://explorer.solana.com/address/Aaa');
        expect(n.transactionUrl('sig'), 'https://explorer.solana.com/tx/sig');
      });

      test('Solana devnet appends ?cluster=devnet', () {
        final n = mk(NetworkType.solana, 'devnet', 'https://explorer.solana.com');
        expect(n.addressUrl('Aaa'),
            'https://explorer.solana.com/address/Aaa?cluster=devnet');
        expect(n.transactionUrl('sig'),
            'https://explorer.solana.com/tx/sig?cluster=devnet');
      });

      test('Solana mainnet-beta alias is bare', () {
        final n =
            mk(NetworkType.solana, 'mainnet-beta', 'https://explorer.solana.com');
        expect(n.addressUrl('Aaa'), 'https://explorer.solana.com/address/Aaa');
      });

      test('No resolved explorer returns empty (host hides link)', () {
        final n = mk(NetworkType.bitcoin, 'bitcoin', '');
        expect(n.addressUrl('addr'), '');
        expect(n.transactionUrl('hash'), '');
      });

      test('fromJson reads ResolvedBlockExplorer', () {
        final n = Network.fromJson({
          'Id': 'net-sol',
          'Type': 'solana',
          'ChainId': 'devnet',
          'Name': 'Solana Devnet',
          'RPC': '',
          'CurrencySymbol': 'SOL',
          'CurrencyDecimals': 9,
          'BlockExplorer': 'auto',
          'ResolvedBlockExplorer': 'https://explorer.solana.com',
          'TestNet': true,
          'Priority': 0,
          'Created': '2024-01-01T00:00:00Z',
          'Updated': '2024-01-01T00:00:00Z',
        });
        expect(n.resolvedBlockExplorer, 'https://explorer.solana.com');
        expect(n.addressUrl('Aaa'),
            'https://explorer.solana.com/address/Aaa?cluster=devnet');
      });
    });
  });

  group('KeyDescription', () {
    test('factory constructors', () {
      final sk = KeyDescription.storeKey('pub123');
      expect(sk.type, 'StoreKey');
      expect(sk.key, 'pub123');

      final rk = KeyDescription.remoteKey('remote123');
      expect(rk.type, 'RemoteKey');

      final pw = KeyDescription.password('secret');
      expect(pw.type, 'Password');
      expect(pw.key, 'secret');
    });

    test('toJson includes Id when present', () {
      final kd = KeyDescription(type: 'StoreKey', key: 'k', id: 'wkey-1');
      final json = kd.toJson();
      expect(json['Id'], 'wkey-1');
      expect(json['Type'], 'StoreKey');
    });

    test('toJson omits Id when null', () {
      final kd = KeyDescription.password('pass');
      expect(kd.toJson().containsKey('Id'), false);
    });
  });

  group('Contact', () {
    test('fromJson parses contact', () {
      final c = Contact.fromJson({
        'Id': 'ct-1',
        'Name': 'Alice',
        'Address': '0xabc',
        'Type': 'ethereum',
        'Flags': ['erc20'],
        'Memo': 'friend',
        'Created': '2024-01-01T00:00:00Z',
        'Updated': '2024-01-01T00:00:00Z',
      });
      expect(c.name, 'Alice');
      expect(c.flags, ['erc20']);
    });
  });

  group('Events', () {
    test('RequestEvent from JSON', () {
      final e = LibwalletEvent.fromJson({
        'result': 'event',
        'event': 'request',
        'data': {'request_id': 'req-123'},
      });
      expect(e, isA<RequestEvent>());
      expect((e as RequestEvent).requestId, 'req-123');
    });

    test('OnlineStatusEvent from JSON', () {
      final e = LibwalletEvent.fromJson({
        'result': 'event',
        'event': 'online_status',
        'data': {'online': true},
      });
      expect(e, isA<OnlineStatusEvent>());
      expect((e as OnlineStatusEvent).isOnline, true);
    });

    test('JsEvent from JSON', () {
      final e = LibwalletEvent.fromJson({
        'result': 'event',
        'event': 'js:chainChanged',
        'data': {'chainId': '0x89'},
      });
      expect(e, isA<JsEvent>());
      expect((e as JsEvent).jsEventName, 'chainChanged');
    });

    test('UnknownEvent for unrecognized events', () {
      final e = LibwalletEvent.fromJson({
        'result': 'event',
        'event': 'custom_event',
        'data': {},
      });
      expect(e, isA<UnknownEvent>());
    });
  });

  group('Asset', () {
    Asset assetWithKey(String key) => Asset(
          id: 'a',
          key: key,
          name: '',
          symbol: '',
          amount: Amount.zero(),
          type: 'fungible',
          network: '',
          testNet: false,
          created: DateTime.parse('2024-01-01T00:00:00Z'),
          updated: DateTime.parse('2024-01-01T00:00:00Z'),
        );

    test('isNative is true for the .NATIVE suffix', () {
      // The Asset.type field is "fungible" for BOTH native and tokens,
      // so hosts can't branch on it. The .NATIVE suffix on Asset.key
      // is libwallet's canonical native-vs-token signal.
      expect(assetWithKey('evm.1.NATIVE').isNative, isTrue);
      expect(assetWithKey('solana.mainnet.NATIVE').isNative, isTrue);
      expect(assetWithKey('bitcoin.bitcoin.NATIVE').isNative, isTrue);
    });

    test('isNative is false for tokens', () {
      expect(assetWithKey('evm.1.0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48')
          .isNative, isFalse);
      expect(assetWithKey('solana.mainnet.EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v')
          .isNative, isFalse);
      expect(assetWithKey('').isNative, isFalse);
      // "NATIVE" must be the trailing segment — a key that contains
      // it elsewhere is still a token.
      expect(assetWithKey('evm.1.NATIVE-extra').isNative, isFalse);
    });

    test('tokenAddress returns the address for tokens, null for native', () {
      expect(
          assetWithKey('evm.1.0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48')
              .tokenAddress,
          '0xA0b86991C6218B36c1d19D4A2e9Eb0cE3606eB48');
      expect(
          assetWithKey('solana.mainnet.EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v')
              .tokenAddress,
          'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
      expect(assetWithKey('evm.1.NATIVE').tokenAddress, isNull);
      expect(assetWithKey('').tokenAddress, isNull);
      expect(assetWithKey('no-dots').tokenAddress, isNull);
    });
  });
}
