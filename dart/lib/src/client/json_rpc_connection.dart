import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../events/events.dart';
import 'request.dart';
import 'response.dart';
import 'transport.dart';

/// Low-level JSON-RPC connection over a Unix socket.
///
/// Handles line-delimited JSON framing, request/response correlation via
/// query_id, progress streaming, and event broadcasting.
class JsonRpcConnection implements Transport {
  final Socket _socket;
  final Map<String, StreamController<LibwalletResponse>> _pending = {};
  final StreamController<LibwalletEvent> _eventController =
      StreamController<LibwalletEvent>.broadcast();
  int _nextId = 0;
  String _buffer = '';
  bool _disposed = false;

  JsonRpcConnection._(this._socket) {
    _socket.listen(
      _onData,
      onError: _onError,
      onDone: _onDone,
    );
  }

  /// Connect to a Unix domain socket at [path].
  static Future<JsonRpcConnection> connect(String path) async {
    final address = InternetAddress(path, type: InternetAddressType.unix);
    final socket = await Socket.connect(address, 0);
    return JsonRpcConnection._(socket);
  }

  /// Wrap an already-connected [socket].
  static JsonRpcConnection fromSocket(Socket socket) {
    return JsonRpcConnection._(socket);
  }

  @override
  Stream<LibwalletEvent> get events => _eventController.stream;

  /// Whether this connection has been disposed.
  bool get isDisposed => _disposed;

  @override
  Stream<LibwalletResponse> send(
    String path,
    String verb, [
    Map<String, dynamic>? params,
  ]) {
    final queryId = _makeQueryId();
    final controller = StreamController<LibwalletResponse>();
    _pending[queryId] = controller;

    final request = LibwalletRequest(
      queryId: queryId,
      verb: verb,
      path: path,
      params: params,
    );

    _socket.write(request.encode());

    return controller.stream;
  }

  @override
  Future<dynamic> request(
    String path,
    String verb, [
    Map<String, dynamic>? params,
  ]) async {
    await for (final resp in send(path, verb, params)) {
      if (resp.isProgress) continue;
      if (resp.isError) throw LibwalletException.fromResponse(resp);
      return resp.data;
    }
    return null;
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    for (final controller in _pending.values) {
      controller.addError(
        const LibwalletException(message: 'Connection closed', code: '-1'),
      );
      controller.close();
    }
    _pending.clear();
    _eventController.close();
    _socket.destroy();
  }

  String _makeQueryId() => 'q_${_nextId++}';

  void _onData(List<int> data) {
    _buffer += utf8.decode(data);
    while (_buffer.contains('\n')) {
      final idx = _buffer.indexOf('\n');
      final line = _buffer.substring(0, idx).trim();
      _buffer = _buffer.substring(idx + 1);
      if (line.isEmpty) continue;
      _handleLine(line);
    }
  }

  void _handleLine(String line) {
    late final Map<String, dynamic> json;
    try {
      json = jsonDecode(line) as Map<String, dynamic>;
    } catch (e) {
      return; // ignore malformed lines
    }

    final resp = LibwalletResponse.fromJson(json);

    // Server-pushed event (no query_id)
    if (resp.isEvent) {
      if (!_eventController.isClosed) {
        _eventController.add(LibwalletEvent.fromJson(json));
      }
      return;
    }

    // Response to a pending request
    final queryId = resp.queryId;
    if (queryId == null) return;

    final controller = _pending[queryId];
    if (controller == null) return;

    controller.add(resp);

    // Close the stream on final response (not progress)
    if (!resp.isProgress) {
      _pending.remove(queryId);
      controller.close();
    }
  }

  void _onError(dynamic error) {
    for (final controller in _pending.values) {
      controller.addError(error);
      controller.close();
    }
    _pending.clear();
  }

  void _onDone() {
    if (!_disposed) {
      dispose();
    }
  }
}
