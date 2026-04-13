/// Fixed-point decimal amount matching Go's wltobj.Amount.
///
/// Wire format: `{"v": "12345", "e": 2, "f": 123.45}`
/// - `v`: significand as a string (big integer)
/// - `e`: exponent (number of decimal places)
/// - `f`: float approximation
class Amount {
  /// Significand of the decimal value as a big integer.
  final BigInt value;

  /// Number of decimal places (exponent).
  final int exp;

  Amount(this.value, this.exp);

  factory Amount.zero([int exp = 0]) => Amount(BigInt.zero, exp);

  factory Amount.fromJson(dynamic json) {
    if (json is Map) {
      final v = json['v'];
      final e = json['e'] as int;
      final value = v is String ? BigInt.parse(v) : BigInt.from(v as num);
      return Amount(value, e);
    }
    throw FormatException('Cannot parse Amount from $json');
  }

  Map<String, dynamic> toJson() => {
        'v': value.toString(),
        'e': exp,
        'f': toDouble(),
      };

  double toDouble() {
    if (exp == 0) return value.toDouble();
    return value / BigInt.from(10).pow(exp);
  }

  bool get isZero => value == BigInt.zero;

  int get sign => value.sign;

  @override
  String toString() {
    if (exp <= 0) return value.toString();
    final s = value.abs().toString().padLeft(exp + 1, '0');
    final intPart = s.substring(0, s.length - exp);
    final fracPart = s.substring(s.length - exp);
    final sign = value.isNegative ? '-' : '';
    return '$sign$intPart.$fracPart';
  }

  @override
  bool operator ==(Object other) =>
      other is Amount && other.value == value && other.exp == exp;

  @override
  int get hashCode => Object.hash(value, exp);
}
