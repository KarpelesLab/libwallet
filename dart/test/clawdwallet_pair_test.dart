import 'dart:async';

import 'package:libwallet/libwallet.dart';
import 'package:libwallet/src/client/response.dart';
import 'package:test/test.dart';

/// Stub transport that returns a pre-baked result (or throws a pre-baked
/// LibwalletException) on the next request() call. The real FFI path is
/// out of scope for these tests; we're verifying the typed-exception
/// dispatcher in ClawdWalletApi.pair only.
class _StubTransport implements Transport {
  Object? _next;
  String? lastPath;
  Map<String, dynamic>? lastParams;

  void willReturn(Map<String, dynamic> data) => _next = data;
  void willThrow(LibwalletException e) => _next = e;

  @override
  Future<dynamic> request(String path, String verb,
      [Map<String, dynamic>? params]) async {
    lastPath = path;
    lastParams = params;
    final n = _next;
    _next = null;
    if (n is LibwalletException) throw n;
    return n;
  }

  @override
  Stream<LibwalletEvent> get events => const Stream.empty();
  @override
  Stream<LibwalletResponse> send(String p, String v,
          [Map<String, dynamic>? params]) =>
      throw UnimplementedError();
  @override
  void dispose() {}
}

void main() {
  late _StubTransport tx;
  late ClawdWalletApi api;

  setUp(() {
    tx = _StubTransport();
    api = ClawdWalletApi(tx);
  });

  test('pair returns AgentIdentity from a success response', () async {
    tx.willReturn({
      'v': 1,
      'agent_spot_id': 'k.AAAA1234',
      'suggested_name': 'laptop',
      'agent_version': 'v0.1.0',
      'capabilities': {'curves': ['ed25519']},
    });
    final id = await api.pair('tibane://pair?agent=k.AAAA1234&token=tok');
    expect(id.agentSpotId, 'k.AAAA1234');
    expect(id.suggestedName, 'laptop');
    expect(id.agentVersion, 'v0.1.0');
    expect(id.capabilities['curves'], ['ed25519']);
    expect(tx.lastPath, 'ClawdWallet:pair');
    expect(tx.lastParams, {'url': 'tibane://pair?agent=k.AAAA1234&token=tok'});
  });

  test('pair tolerates missing optional fields and null capabilities', () async {
    tx.willReturn({
      'v': 1,
      'agent_spot_id': 'k.BBB',
      'capabilities': null,
    });
    final id = await api.pair('tibane://pair?agent=k.BBB&token=t');
    expect(id.suggestedName, '');
    expect(id.agentVersion, '');
    expect(id.capabilities, isEmpty);
  });

  // Each Go sentinel surfaces as LibwalletException(message=<code>) at the
  // FFI boundary. These tests exercise the dispatcher in pair() that maps
  // those to typed PairingException subclasses.
  final codeToException = <String, Type>{
    'url_malformed': PairingURLMalformedException,
    'agent_unreachable': PairingAgentUnreachableException,
    'token_invalid': PairingTokenInvalidException,
    'token_expired': PairingTokenExpiredException,
    'token_consumed': PairingTokenConsumedException,
    'bad_request': PairingBadRequestException,
    'identity_mismatch': PairingIdentityMismatchException,
  };

  for (final entry in codeToException.entries) {
    test('${entry.key} → ${entry.value}', () async {
      tx.willThrow(LibwalletException(message: entry.key, code: '500'));
      await expectLater(
        api.pair('tibane://pair?agent=k.X&token=t'),
        throwsA(isA<PairingException>().having(
            (e) => e.runtimeType, 'runtimeType', entry.value)),
      );
    });
  }

  test('wrapped Go errors (fmt.Errorf %w) still dispatch correctly', () async {
    // The Go side wraps agent_unreachable with the underlying transport
    // error: "agent_unreachable: connection refused". Verify the substring
    // match in the dispatcher recognises it.
    tx.willThrow(LibwalletException(
        message: 'agent_unreachable: connection refused', code: '500'));
    await expectLater(
      api.pair('tibane://pair?agent=k.X&token=t'),
      throwsA(isA<PairingAgentUnreachableException>()),
    );
  });

  test('unknown error code falls back to bad_request (fail closed)', () async {
    tx.willThrow(
        LibwalletException(message: 'who_knows', code: '500'));
    await expectLater(
      api.pair('tibane://pair?agent=k.X&token=t'),
      throwsA(isA<PairingBadRequestException>()),
    );
  });

  test('LibwalletException is never re-thrown — only PairingException',
      () async {
    tx.willThrow(LibwalletException(message: 'token_expired', code: '500'));
    try {
      await api.pair('tibane://pair?agent=k.X&token=t');
      fail('expected throw');
    } catch (e) {
      expect(e, isA<PairingException>());
      expect(e, isNot(isA<LibwalletException>()));
    }
  });
}
