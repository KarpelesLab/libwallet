/// A response from the libwallet JSON-RPC socket.
class LibwalletResponse {
  final String? queryId;
  final String result;
  final String? status;
  final dynamic data;
  final String? error;
  final dynamic code;
  final String? requestId;
  final double? time;

  const LibwalletResponse({
    this.queryId,
    required this.result,
    this.status,
    this.data,
    this.error,
    this.code,
    this.requestId,
    this.time,
  });

  factory LibwalletResponse.fromJson(Map<String, dynamic> json) {
    return LibwalletResponse(
      queryId: json['query_id'] as String?,
      result: json['result'] as String? ?? '',
      status: json['status'] as String?,
      data: json['data'],
      error: json['error'] as String?,
      code: json['code'],
      requestId: json['request_id'] as String?,
      time: (json['time'] as num?)?.toDouble(),
    );
  }

  bool get isSuccess => result == 'success' || status == 'success';
  bool get isError => error != null;
  bool get isProgress => result == 'progress';
  bool get isEvent => result == 'event';
}

/// Exception thrown when libwallet returns an error response.
class LibwalletException implements Exception {
  final String message;
  final String code;
  final String? token;

  const LibwalletException({
    required this.message,
    required this.code,
    this.token,
  });

  factory LibwalletException.fromResponse(LibwalletResponse resp) {
    return LibwalletException(
      message: resp.error ?? 'Unknown error',
      code: resp.code?.toString() ?? '0',
      token: resp.status,
    );
  }

  @override
  String toString() => 'LibwalletException($code): $message';
}

/// Represents either a progress update or a completed result.
sealed class ProgressOr<T> {
  const ProgressOr();
}

/// A progress update during a long-running operation — a single fraction
/// between 0.0 (just started) and 1.0 (complete). The Go side reports
/// fine-grained progress (e.g. one tick per safe prime found during ECDSA
/// pre-param generation) mapped into a smooth 0..1 range so consumers can
/// bind it directly to a progress bar without worrying about phases.
class Progress<T> extends ProgressOr<T> {
  /// Progress fraction in the range `[0.0, 1.0]`.
  final double fraction;

  const Progress(this.fraction);
}

/// The completed result of a long-running operation.
class Complete<T> extends ProgressOr<T> {
  final T value;

  const Complete(this.value);
}
