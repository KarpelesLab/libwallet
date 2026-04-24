// Statically-linked Objective-C bridge to libwallet's Go-compiled
// FFI entry points. The Dart side looks up the snake_case names
// below via dart:ffi (DynamicLibrary.process() → dlsym); each
// bridge function then forwards the call to the underlying
// Libwallet* symbol from the force-loaded libwallet.xcframework.
//
// Why we need a bridge at all: dart:ffi on iOS only knows
// DynamicLibrary.process() (= dlsym(RTLD_DEFAULT)), and dlsym
// searches the host binary's export trie. Symbols pulled in via
// `-force_load libwallet.xcframework/.../libwallet.a` survive
// dead-strip (the code is in the binary) but Apple's new linker
// (ld-prime, Xcode 15+) does NOT add them to the export trie
// unless something in the host's app sources statically references
// them — at which point they're treated as "used" symbols with
// default export visibility.
//
// Earlier sessions tried to keep the Go symbols in the export trie
// by other means:
//   - `-exported_symbol` (an EXCLUSIVE allowlist that stripped
//     everything else, including `_main` — broke Xcode 16's debug
//     dylib launcher);
//   - `-u` (forces the linker to resolve the symbol but on the
//     new linker doesn't guarantee export-trie inclusion for
//     release builds; debug-only fix that leaks on release).
// Both were ldflag escape hatches against fundamentally fragile
// linker behavior. This bridge is the standard-pattern fix: a real
// static call from app source to each FFI symbol, which makes the
// linker see them as genuinely used and emits both the bridge AND
// its callees into the host's export trie under default visibility.
//
// `__attribute__((used))` keeps each bridge function from being
// dead-stripped itself — the compiler doesn't know Dart will dlsym
// them at runtime, so without `used` the same dead-strip pass that
// removed the Go symbols would remove the bridges too.
//
// Signatures must stay byte-identical to the corresponding Go
// `//export` declarations in cshared/ffi.go — Dart's FFI marshalling
// depends on it. If a new entry point is added there, mirror it
// here AND wire it up in dart/lib/src/client/ffi_transport.dart.

#import <Foundation/Foundation.h>
#include <stdint.h>

typedef void (*libwallet_response_callback)(const char *response_json, uintptr_t user_data);
typedef void (*libwallet_event_callback)(const char *event_json, uintptr_t user_data);

// Forward declarations — definitions live in the force-loaded
// libwallet.xcframework static archive (Go cshared/ffi.go).
extern uintptr_t LibwalletInit(const char *dataDir);
extern void LibwalletRequest(uintptr_t h, const char *requestJson,
                             libwallet_response_callback cb,
                             uintptr_t userData);
extern void LibwalletSetEventCallback(uintptr_t h,
                                      libwallet_event_callback cb,
                                      uintptr_t userData);
extern void LibwalletShowDebug(void);
extern void LibwalletDestroy(uintptr_t h);
extern void LibwalletFree(char *ptr);

// Bridge wrappers — exposed via default visibility, kept alive
// across dead-strip via `used`.

__attribute__((used))
uintptr_t libwallet_init(const char *dataDir) {
    return LibwalletInit(dataDir);
}

__attribute__((used))
void libwallet_request(uintptr_t h, const char *requestJson,
                       libwallet_response_callback cb,
                       uintptr_t userData) {
    LibwalletRequest(h, requestJson, cb, userData);
}

__attribute__((used))
void libwallet_set_event_callback(uintptr_t h,
                                  libwallet_event_callback cb,
                                  uintptr_t userData) {
    LibwalletSetEventCallback(h, cb, userData);
}

__attribute__((used))
void libwallet_show_debug(void) {
    LibwalletShowDebug();
}

__attribute__((used))
void libwallet_destroy(uintptr_t h) {
    LibwalletDestroy(h);
}

__attribute__((used))
void libwallet_free(char *ptr) {
    LibwalletFree(ptr);
}
