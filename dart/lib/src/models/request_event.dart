/// A Web3 request pending user approval.
class PendingRequest {
  /// Unique request identifier.
  final String id;

  /// Request type: `connect`, `sign`, `personal_sign`, `eth_signTypedData`, etc.
  final String type;

  /// Current status: `pending`, `accepted`, `rejected`, or `timedout`.
  final String status;

  /// Hostname of the dApp that initiated the request.
  final String? host;

  /// Transaction payload to be signed, if applicable.
  final dynamic transaction;

  /// Arbitrary value associated with the request (e.g. message to sign).
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
