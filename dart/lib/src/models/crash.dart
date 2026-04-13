/// A crash event record.
class Crash {
  /// Unique identifier for this crash report.
  final String id;

  /// Location in code where the crash occurred.
  final String where;

  /// Error message describing the crash.
  final String message;

  /// Full stack trace at the time of the crash.
  final String stack;

  /// Timestamp when the crash was recorded.
  final DateTime created;

  const Crash({
    required this.id,
    required this.where,
    required this.message,
    required this.stack,
    required this.created,
  });

  factory Crash.fromJson(Map<String, dynamic> json) {
    return Crash(
      id: json['Id'] as String,
      where: json['Where'] as String? ?? '',
      message: json['Message'] as String? ?? '',
      stack: json['Stack'] as String? ?? '',
      created: DateTime.parse(json['Created'] as String),
    );
  }
}
