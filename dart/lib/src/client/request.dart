import 'dart:convert';

/// A request to send to the libwallet JSON-RPC socket.
class LibwalletRequest {
  final String queryId;
  final String verb;
  final String path;
  final Map<String, dynamic>? params;

  const LibwalletRequest({
    required this.queryId,
    required this.verb,
    required this.path,
    this.params,
  });

  Map<String, dynamic> toJson() => {
        'query_id': queryId,
        'verb': verb,
        'path': path,
        if (params != null) 'params': params,
      };

  /// Encode as a newline-terminated JSON string for the wire protocol.
  String encode() => '${jsonEncode(toJson())}\n';
}
