import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io' show Platform;

import 'package:ffi/ffi.dart';

import '../events/events.dart';
import 'response.dart';
import 'transport.dart';

// C function signatures from the Go c-shared library
typedef _LibwalletInitC = UintPtr Function(Pointer<Utf8> dataDir);
typedef _LibwalletInitDart = int Function(Pointer<Utf8> dataDir);

typedef _ResponseCallbackC = Void Function(
    Pointer<Utf8> responseJson, UintPtr userData);

typedef _EventCallbackC = Void Function(
    Pointer<Utf8> eventJson, UintPtr userData);

typedef _LibwalletRequestC = Void Function(
  UintPtr handle,
  Pointer<Utf8> requestJson,
  Pointer<NativeFunction<_ResponseCallbackC>> cb,
  UintPtr userData,
);
typedef _LibwalletRequestDart = void Function(
  int handle,
  Pointer<Utf8> requestJson,
  Pointer<NativeFunction<_ResponseCallbackC>> cb,
  int userData,
);

typedef _LibwalletSetEventCallbackC = Void Function(
  UintPtr handle,
  Pointer<NativeFunction<_EventCallbackC>> cb,
  UintPtr userData,
);
typedef _LibwalletSetEventCallbackDart = void Function(
  int handle,
  Pointer<NativeFunction<_EventCallbackC>> cb,
  int userData,
);

typedef _LibwalletDestroyC = Void Function(UintPtr handle);
typedef _LibwalletDestroyDart = void Function(int handle);

typedef _LibwalletFreeC = Void Function(Pointer<Utf8> ptr);
typedef _LibwalletFreeDart = void Function(Pointer<Utf8> ptr);

/// FFI-based transport that communicates with the Go library via direct function calls.
///
/// Uses [NativeCallable.listener] to receive callbacks from Go goroutines,
/// which are safely posted to Dart's event loop.
class FfiTransport implements Transport {
  final int _handle;
  final _LibwalletRequestDart _requestFn;
  final _LibwalletFreeDart _freeFn;
  final _LibwalletDestroyDart _destroyFn;

  final StreamController<LibwalletEvent> _eventController =
      StreamController<LibwalletEvent>.broadcast();

  // Pending requests: userData (int) → StreamController for responses
  final Map<int, StreamController<LibwalletResponse>> _pending = {};
  int _nextId = 1; // start at 1, 0 reserved for events

  // NativeCallable instances (must be kept alive)
  late final NativeCallable<_ResponseCallbackC> _responseCallable;
  late final NativeCallable<_EventCallbackC> _eventCallable;

  bool _disposed = false;

  late final _LibwalletSetEventCallbackDart _setEventCallbackFn;
  bool _eventsInitialized = false;

  FfiTransport._({
    required int handle,
    required _LibwalletRequestDart requestFn,
    required _LibwalletFreeDart freeFn,
    required _LibwalletDestroyDart destroyFn,
    required _LibwalletSetEventCallbackDart setEventCallbackFn,
  })  : _handle = handle,
        _requestFn = requestFn,
        _freeFn = freeFn,
        _destroyFn = destroyFn,
        _setEventCallbackFn = setEventCallbackFn {
    // Create NativeCallable.listener for response callback.
    // This is safe to call from any Go goroutine.
    _responseCallable =
        NativeCallable<_ResponseCallbackC>.listener(_onResponse);

    // Create NativeCallable.listener for event callback.
    _eventCallable = NativeCallable<_EventCallbackC>.listener(_onEvent);
  }

  /// Initialize the event bridge. Called lazily on first access to [events].
  void _initEvents() {
    if (_eventsInitialized || _disposed) return;
    _eventsInitialized = true;
    _setEventCallbackFn(
        _handle, _eventCallable.nativeFunction, 0);
  }

  /// Initialize the Go library and create an FFI transport.
  static FfiTransport initialize(String dataDir, {DynamicLibrary? library}) {
    final lib = library ?? _loadDefaultLibrary();

    // Symbol names: on iOS we look up the snake_case bridges defined
    // in dart/ios/Classes/LibwalletBridge.m, which statically forward
    // to the underlying Go-exported `Libwallet*` symbols. The bridge
    // gives the linker a real static reference from app source code,
    // which is what keeps the symbols in the host binary's export
    // trie under default visibility — Apple's new linker (ld-prime,
    // Xcode 15+) drops force-loaded symbols from the export trie
    // unless something app-side references them, and dart:ffi has
    // no way to look up symbols outside the export trie. See the
    // bridge file for the full background.
    //
    // On every other platform the Go-exported names are reachable
    // directly: macOS / Linux / Windows ship as a c-shared dylib
    // that we dlopen (its export trie is whatever Go emits), and
    // Android's c-shared .so is bundled by Gradle the same way.
    final initSym = Platform.isIOS ? 'libwallet_init' : 'LibwalletInit';
    final requestSym = Platform.isIOS ? 'libwallet_request' : 'LibwalletRequest';
    final setEventCbSym = Platform.isIOS
        ? 'libwallet_set_event_callback'
        : 'LibwalletSetEventCallback';
    final destroySym = Platform.isIOS ? 'libwallet_destroy' : 'LibwalletDestroy';
    final freeSym = Platform.isIOS ? 'libwallet_free' : 'LibwalletFree';

    final init =
        lib.lookupFunction<_LibwalletInitC, _LibwalletInitDart>(initSym);
    final request = lib
        .lookupFunction<_LibwalletRequestC, _LibwalletRequestDart>(requestSym);
    final setEventCb = lib.lookupFunction<_LibwalletSetEventCallbackC,
        _LibwalletSetEventCallbackDart>(setEventCbSym);
    final destroy = lib
        .lookupFunction<_LibwalletDestroyC, _LibwalletDestroyDart>(destroySym);
    final free =
        lib.lookupFunction<_LibwalletFreeC, _LibwalletFreeDart>(freeSym);

    final dataDirPtr = dataDir.toNativeUtf8();
    final handle = init(dataDirPtr);
    malloc.free(dataDirPtr);

    if (handle == 0) {
      throw const LibwalletException(
          message: 'Failed to initialize libwallet', code: '-1');
    }

    return FfiTransport._(
      handle: handle,
      requestFn: request,
      freeFn: free,
      destroyFn: destroy,
      setEventCallbackFn: setEventCb,
    );
  }

  static DynamicLibrary _loadDefaultLibrary() {
    // Try to load from the native assets system or default paths
    return DynamicLibrary.open('liblibwallet.dylib');
  }

  @override
  Stream<LibwalletEvent> get events {
    _initEvents();
    return _eventController.stream;
  }

  @override
  Stream<LibwalletResponse> send(String path, String verb,
      [Map<String, dynamic>? params]) {
    final id = _nextId++;
    final controller = StreamController<LibwalletResponse>();
    _pending[id] = controller;

    final reqJson = jsonEncode({
      'path': path,
      'verb': verb,
      if (params != null) 'params': params,
    });

    final reqPtr = reqJson.toNativeUtf8();
    _requestFn(
        _handle, reqPtr, _responseCallable.nativeFunction, id);
    malloc.free(reqPtr);

    return controller.stream;
  }

  @override
  Future<dynamic> request(String path, String verb,
      [Map<String, dynamic>? params]) async {
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

    // Clean up pending requests
    for (final controller in _pending.values) {
      controller.addError(
        const LibwalletException(message: 'Transport closed', code: '-1'),
      );
      controller.close();
    }
    _pending.clear();
    _eventController.close();

    // Destroy the Go handle (closes event bridge FD, which causes the
    // event reader goroutine to exit). It may fire one last callback,
    // which is safely ignored by the _disposed guard above.
    _destroyFn(_handle);

    // Do NOT close NativeCallable instances here. Go goroutines may still
    // be delivering in-flight callbacks on native threads. Closing the
    // NativeCallable while a native thread is invoking it causes a VM crash
    // ("Callback invoked after it has been deleted"). Instead, we rely on
    // the _disposed guard to ignore late callbacks, and let the Dart VM
    // clean up the NativeCallable instances on isolate shutdown.
  }

  /// Response callback — called from Go goroutine via NativeCallable.listener
  void _onResponse(Pointer<Utf8> jsonPtr, int userData) {
    final jsonStr = jsonPtr.toDartString();
    _freeFn(jsonPtr); // Free the C string allocated by Go

    if (_disposed) return; // Ignore callbacks after dispose

    final json = jsonDecode(jsonStr) as Map<String, dynamic>;
    final resp = LibwalletResponse.fromJson(json);

    final controller = _pending[userData];
    if (controller == null) return;

    controller.add(resp);

    // Close stream on final response (not progress)
    if (!resp.isProgress) {
      _pending.remove(userData);
      controller.close();
    }
  }

  /// Event callback — called from Go goroutine via NativeCallable.listener
  void _onEvent(Pointer<Utf8> jsonPtr, int userData) {
    final jsonStr = jsonPtr.toDartString();
    _freeFn(jsonPtr);

    if (_disposed) return; // Ignore callbacks after dispose

    final json = jsonDecode(jsonStr) as Map<String, dynamic>;

    // Events from BroadcastJson have {"result":"event","event":"...","data":{...}}
    final result = json['result'] as String?;
    if (result == 'event') {
      if (!_eventController.isClosed) {
        _eventController.add(LibwalletEvent.fromJson(json));
      }
    }
    // Ignore non-event messages on the event channel (e.g., responses to
    // the dummy jsonclient requests — the event FD also receives those)
  }
}
