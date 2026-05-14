/// Fixed-point decimal amount matching Go's wltobj.Amount.
///
/// Wire format: `{"v": "12345", "e": 2, "f": 123.45}`
/// - `v`: significand as a string (big integer)
/// - `e`: exponent (number of decimal places)
/// - `f`: float approximation
///
/// **MAX sentinel** — see [Amount.max] / [isMax]. A deferred "use the
/// maximum sendable amount" marker that the libwallet build path
/// resolves at the last possible moment using the actual tx contents
/// (recipient, calldata, gas estimate). Send a MAX-Amount in
/// `Transaction.amount` and trust libwallet to compute `balance -
/// actual-fee` at signAndSend time. Eliminates the
/// `transactions.maxSendable` → `transactions.signAndSend` race where
/// the gas price or balance can drift between the two calls. Wire
/// form: `{"v": "MAX", "e": <decimals>}`.
class Amount {
  /// Significand of the decimal value as a big integer. Zero (default)
  /// when [isMax] is true; the build path will replace it.
  final BigInt value;

  /// Number of decimal places (exponent).
  final int exp;

  /// True when this is the MAX sentinel — see the class doc. Most
  /// callers ignore this; they construct `Amount.max(decimals)` and
  /// hand the result to libwallet.
  final bool isMax;

  const Amount(this.value, this.exp) : isMax = false;

  Amount._max(this.exp)
      : value = BigInt.zero,
        isMax = true;

  /// MAX sentinel. Pass [decimals] matching the asset (so the resolved
  /// amount inherits the right exponent — same value libwallet uses
  /// internally).
  factory Amount.max(int decimals) => Amount._max(decimals);

  factory Amount.zero([int exp = 0]) => Amount(BigInt.zero, exp);

  factory Amount.fromJson(dynamic json) {
    if (json is String && json == 'MAX') {
      return Amount.max(0);
    }
    if (json is Map) {
      final v = json['v'];
      final e = json['e'] as int;
      if (v is String && v == 'MAX') {
        return Amount.max(e);
      }
      final value = v is String ? BigInt.parse(v) : BigInt.from(v as num);
      return Amount(value, e);
    }
    throw FormatException('Cannot parse Amount from $json');
  }

  Map<String, dynamic> toJson() {
    if (isMax) {
      return {'v': 'MAX', 'e': exp};
    }
    return {
      'v': value.toString(),
      'e': exp,
      'f': toDouble(),
    };
  }

  double toDouble() {
    if (isMax) return double.nan;
    if (exp == 0) return value.toDouble();
    return value / BigInt.from(10).pow(exp);
  }

  bool get isZero => value == BigInt.zero && !isMax;

  int get sign => isMax ? 0 : value.sign;

  @override
  String toString() {
    if (isMax) return 'MAX';
    if (exp <= 0) return value.toString();
    final s = value.abs().toString().padLeft(exp + 1, '0');
    final intPart = s.substring(0, s.length - exp);
    final fracPart = s.substring(s.length - exp);
    final sign = value.isNegative ? '-' : '';
    return '$sign$intPart.$fracPart';
  }

  @override
  bool operator ==(Object other) =>
      other is Amount &&
      other.value == value &&
      other.exp == exp &&
      other.isMax == isMax;

  @override
  int get hashCode => Object.hash(value, exp, isMax);
}

