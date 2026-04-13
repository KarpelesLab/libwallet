/// A Web3 request pending user approval.
class PendingRequest {
  final String id;
  final String type;
  final String status;
  final String? host;
  final dynamic transaction;
  final dynamic value;

  const PendingRequest({
    required this.id,
    required this.type,
    required this.status,
    this.host,
    this.transaction,
    this.value,
  });

  factory PendingRequest.fromJson(Map<String, dynamic> json) {
    return PendingRequest(
      id: json['Id'] as String? ?? json['request_id'] as String? ?? '',
      type: json['Type'] as String? ?? '',
      status: json['Status'] as String? ?? '',
      host: json['Host'] as String?,
      transaction: json['Transaction'],
      value: json['Value'],
    );
  }

  bool get isPending => status == 'pending';
  bool get isAccepted => status == 'accepted';
  bool get isRejected => status == 'rejected';
  bool get isTimedOut => status == 'timedout';
}
