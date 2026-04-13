import 'dart:convert';

import 'package:test/test.dart';
import 'package:libwallet/src/client/request.dart';

void main() {
  group('LibwalletRequest', () {
    test('encodes GET request', () {
      final req = LibwalletRequest(
        queryId: 'q_0',
        verb: 'GET',
        path: 'Wallet',
      );
      final json = jsonDecode(req.encode().trim());
      expect(json['query_id'], 'q_0');
      expect(json['verb'], 'GET');
      expect(json['path'], 'Wallet');
      expect(json.containsKey('params'), false);
    });

    test('encodes POST request with params', () {
      final req = LibwalletRequest(
        queryId: 'q_1',
        verb: 'POST',
        path: 'Wallet',
        params: {
          'Name': 'Test',
          'Keys': [
            {'Type': 'Password', 'Key': 'pass123'}
          ],
        },
      );
      final json = jsonDecode(req.encode().trim());
      expect(json['verb'], 'POST');
      expect(json['params']['Name'], 'Test');
      expect(json['params']['Keys'], hasLength(1));
    });

    test('encode ends with newline', () {
      final req = LibwalletRequest(
        queryId: 'q_2',
        verb: 'GET',
        path: 'Info:ping',
      );
      expect(req.encode().endsWith('\n'), true);
    });
  });
}
