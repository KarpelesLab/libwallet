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
}
