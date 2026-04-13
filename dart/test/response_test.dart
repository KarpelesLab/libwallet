import 'package:test/test.dart';
import 'package:libwallet/src/client/response.dart';

void main() {
  group('LibwalletResponse', () {
    test('parses success response', () {
      final resp = LibwalletResponse.fromJson({
        'query_id': 'q_0',
        'result': 'success',
        'status': 'success',
        'data': {'Id': 'wlt-abc123'},
        'time': 0.042,
      });
      expect(resp.isSuccess, true);
      expect(resp.isError, false);
      expect(resp.isProgress, false);
      expect(resp.queryId, 'q_0');
      expect((resp.data as Map)['Id'], 'wlt-abc123');
    });

    test('parses error response', () {
      final resp = LibwalletResponse.fromJson({
        'query_id': 'q_1',
        'result': 'error',
        'error': 'insufficient balance',
        'code': 400,
      });
      expect(resp.isError, true);
      expect(resp.isSuccess, false);
      expect(resp.error, 'insufficient balance');
      expect(resp.code, 400);
    });

    test('parses progress response', () {
      final resp = LibwalletResponse.fromJson({
        'query_id': 'q_2',
        'result': 'progress',
        'data': {'count': 6, 'running': 3},
      });
      expect(resp.isProgress, true);
      expect(resp.isSuccess, false);
    });

    test('parses event', () {
      final resp = LibwalletResponse.fromJson({
        'result': 'event',
        'event': 'request',
        'data': {'request_id': 'req-123'},
      });
      expect(resp.isEvent, true);
      expect(resp.queryId, isNull);
    });
  });

  group('LibwalletException', () {
    test('fromResponse creates exception', () {
      final resp = LibwalletResponse.fromJson({
        'query_id': 'q_1',
        'result': 'error',
        'error': 'wrong password',
        'code': 403,
      });
      final ex = LibwalletException.fromResponse(resp);
      expect(ex.message, 'wrong password');
      expect(ex.code, '403');
      expect(ex.toString(), contains('wrong password'));
    });
  });

  group('ProgressOr', () {
    test('Progress holds count and running', () {
      const p = Progress<String>(6, 3);
      expect(p.count, 6);
      expect(p.running, 3);
      expect(p.fraction, closeTo(3 / 7, 0.001));
    });

    test('Complete holds value', () {
      const c = Complete<String>('done');
      expect(c.value, 'done');
    });

    test('pattern matching works', () {
      ProgressOr<int> event = const Complete(42);
      switch (event) {
        case Progress():
          fail('Should be Complete');
        case Complete(:final value):
          expect(value, 42);
      }

      final event2 = const Progress<int>(10, 5);
      expect(event2.count, 10);
      expect(event2.running, 5);
    });
  });
}
