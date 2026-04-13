/// A crash event record.
class Crash {
  final String id;
  final String where;
  final String message;
  final String stack;
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
