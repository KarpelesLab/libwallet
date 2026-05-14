import 'package:test/test.dart';
import 'package:libwallet/libwallet.dart';

void main() {
  group('Amount', () {
    test('fromJson parses wire format', () {
      final a = Amount.fromJson({'v': '12345', 'e': 2, 'f': 123.45});
      expect(a.value, BigInt.from(12345));
      expect(a.exp, 2);
    });

    test('fromJson parses numeric v', () {
      final a = Amount.fromJson({'v': 100, 'e': 0, 'f': 100.0});
      expect(a.value, BigInt.from(100));
      expect(a.exp, 0);
    });

    test('toDouble works', () {
      final a = Amount(BigInt.from(12345), 2);
      expect(a.toDouble(), closeTo(123.45, 0.001));
    });

    test('toDouble with zero exp', () {
      final a = Amount(BigInt.from(42), 0);
      expect(a.toDouble(), 42.0);
    });

    test('toString formats correctly', () {
      expect(Amount(BigInt.from(12345), 2).toString(), '123.45');
      expect(Amount(BigInt.from(100), 0).toString(), '100');
      expect(Amount(BigInt.from(1), 8).toString(), '0.00000001');
      expect(Amount(BigInt.from(-500), 2).toString(), '-5.00');
    });

    test('toJson roundtrips', () {
      final a = Amount(BigInt.from(12345), 2);
      final json = a.toJson();
      expect(json['v'], '12345');
      expect(json['e'], 2);
      expect(json['f'], closeTo(123.45, 0.001));

      final b = Amount.fromJson(json);
      expect(b.value, a.value);
      expect(b.exp, a.exp);
    });

    test('isZero', () {
      expect(Amount.zero().isZero, true);
      expect(Amount(BigInt.from(1), 0).isZero, false);
    });

    test('sign', () {
      expect(Amount(BigInt.from(5), 0).sign, 1);
      expect(Amount(BigInt.from(-5), 0).sign, -1);
      expect(Amount.zero().sign, 0);
    });

    test('equality', () {
      final a = Amount(BigInt.from(100), 2);
      final b = Amount(BigInt.from(100), 2);
      final c = Amount(BigInt.from(100), 3);
      expect(a, equals(b));
      expect(a, isNot(equals(c)));
    });

    group('MAX sentinel', () {
      test('Amount.max constructs the sentinel', () {
        final a = Amount.max(18);
        expect(a.isMax, isTrue);
        expect(a.exp, 18);
        expect(a.sign, 0);
        expect(a.toString(), 'MAX');
      });

      test('regular Amount has isMax false', () {
        final a = Amount(BigInt.from(100), 2);
        expect(a.isMax, isFalse);
      });

      test('toJson emits MAX sentinel with exp', () {
        final j = Amount.max(9).toJson();
        expect(j['v'], 'MAX');
        expect(j['e'], 9);
        // No "f" key — it would be NaN, which doesn't round-trip cleanly.
        expect(j.containsKey('f'), isFalse);
      });

      test('fromJson recognises MAX in object form', () {
        final a = Amount.fromJson({'v': 'MAX', 'e': 6});
        expect(a.isMax, isTrue);
        expect(a.exp, 6);
      });

      test('fromJson recognises bare "MAX" string', () {
        final a = Amount.fromJson('MAX');
        expect(a.isMax, isTrue);
      });

      test('isZero is false for MAX (distinct from a true zero amount)', () {
        expect(Amount.max(0).isZero, isFalse);
        expect(Amount.zero(0).isZero, isTrue);
      });

      test('equality treats MAX as distinct from zero with same exp', () {
        expect(Amount.max(6) == Amount.zero(6), isFalse);
        expect(Amount.max(6) == Amount.max(6), isTrue);
      });
    });
  });
}
