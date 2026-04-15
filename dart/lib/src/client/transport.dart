import 'dart:async';

import '../events/events.dart';
import 'response.dart';

/// Abstract transport layer for communicating with the Go library.
///
/// The only implementation is [FfiTransport] — direct FFI calls via
/// `dart:ffi` + `NativeCallable.listener`. The interface is kept
/// abstract so tests can mock it.
abstract class Transport {
  /// Stream of server-pushed events.
  Stream<LibwalletEvent> get events;

  /// Send a request that may yield progress updates, then a final response.
  Stream<LibwalletResponse> send(String path, String verb,
      [Map<String, dynamic>? params]);

  /// Send a request and return just the final response data.
  /// Throws [LibwalletException] on error.
  Future<dynamic> request(String path, String verb,
      [Map<String, dynamic>? params]);

  /// Close the transport and clean up resources.
  void dispose();
}
