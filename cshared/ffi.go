// Package main provides C-shared library exports for libwallet.
// Build with: go build -buildmode=c-shared -o liblibwallet.dylib ./cshared/
package main

/*
#include <stdlib.h>
#include <stdint.h>

typedef void (*response_callback)(const char* response_json, uintptr_t user_data);
typedef void (*event_callback)(const char* event_json, uintptr_t user_data);

// Trampolines: Go can't call C function pointers directly, so we use C helper functions.
static inline void call_response_cb(response_callback cb, const char* json, uintptr_t user_data) {
	cb(json, user_data);
}
static inline void call_event_cb(event_callback cb, const char* json, uintptr_t user_data) {
	cb(json, user_data);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltbase"
)

// handle stores the environment and event bridge for one LibwalletInit session.
type handle struct {
	env any // the wltbase environment

	// mu serializes lifecycle operations: it guards eventConn/eventDone and,
	// crucially, serializes every wg.Add against Destroy's wg.Wait so a
	// WaitGroup is never reused before a previous Wait has returned.
	mu        sync.Mutex
	eventConn net.Conn      // the event reader connection (closed on destroy / re-register)
	eventDone chan struct{} // closed when the event reader goroutine exits

	shutdown atomic.Bool
	wg       sync.WaitGroup // tracks active goroutines that may call back into C
}

var (
	handles   sync.Map // map[uintptr]*handle
	handleSeq atomic.Uintptr
)

// zero wipes a transient Go byte buffer that may have held secret material
// (mnemonics, passwords, keys) before it is dropped on the floor for the GC.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func storeHandle(v *handle) C.uintptr_t {
	id := handleSeq.Add(1)
	handles.Store(id, v)
	return C.uintptr_t(id)
}

func loadHandle(h C.uintptr_t) *handle {
	v, ok := handles.Load(uintptr(h))
	if !ok {
		return nil
	}
	return v.(*handle)
}

func deleteHandle(h C.uintptr_t) {
	handles.Delete(uintptr(h))
}

// ffiSink implements apirouter.ResponseSink to forward progress updates via callback.
type ffiSink struct {
	cb       C.response_callback
	userData C.uintptr_t
	hdl      *handle
}

func (f *ffiSink) SendResponse(r *apirouter.Response) (err error) {
	// A panic here unwinds across the cgo callback boundary and would crash
	// the host app; convert it into a returned error instead.
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error(fmt.Sprintf("ffiSink.SendResponse panic: %v", rec))
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	if f.hdl.shutdown.Load() {
		return nil // don't call back after shutdown
	}
	data, err := r.MarshalJSON()
	if err != nil {
		return err
	}
	cstr := C.CString(string(data))
	// The secret now lives in the C string (freed via LibwalletFree); wipe the
	// transient Go buffer so it does not linger in freed Go heap.
	zero(data)
	C.call_response_cb(f.cb, cstr, f.userData)
	return nil
}

// LibwalletInit initializes the libwallet environment.
// Returns an opaque handle (>0) on success, 0 on failure.
//
//export LibwalletInit
func LibwalletInit(dataDir *C.char) (result C.uintptr_t) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error(fmt.Sprintf("LibwalletInit panic: %v", r))
			result = 0
		}
	}()

	dir := C.GoString(dataDir)
	e, err := wltbase.InitEnv(dir)
	if err != nil {
		slog.Error(fmt.Sprintf("LibwalletInit failed: %v", err))
		return 0
	}

	h := &handle{env: e}
	return storeHandle(h)
}

// LibwalletRequest sends a JSON-RPC request and calls cb with the response.
// The request is processed asynchronously in a goroutine.
// The callback may be called multiple times: once for each progress update,
// then once for the final response.
// The caller must free returned C strings with LibwalletFree.
//
//export LibwalletRequest
func LibwalletRequest(h C.uintptr_t, requestJson *C.char, cb C.response_callback, userData C.uintptr_t) {
	// Catch any panic before the worker goroutine is launched (e.g. from
	// loadHandle/GoString) and turn it into an error response instead of
	// unwinding across the cgo boundary and crashing the host app.
	defer func() {
		if r := recover(); r != nil {
			slog.Error(fmt.Sprintf("LibwalletRequest panic: %v", r))
			cstr := C.CString(fmt.Sprintf(`{"result":"error","error":%q,"code":500}`, fmt.Sprintf("panic: %v", r)))
			C.call_response_cb(cb, cstr, userData)
		}
	}()

	hdl := loadHandle(h)
	if hdl == nil {
		cstr := C.CString(`{"result":"error","error":"invalid handle","code":500}`)
		C.call_response_cb(cb, cstr, userData)
		return
	}

	reqStr := C.GoString(requestJson)

	// Gate new work behind the shutdown flag and serialize wg.Add against
	// Destroy's wg.Wait under hdl.mu. Without this, wg.Add could run
	// concurrently with (or after) wg.Wait, panicking the WaitGroup
	// ("reused before previous Wait has returned") and letting a callback
	// fire after Destroy returned (use-after-free for the C consumer).
	hdl.mu.Lock()
	if hdl.shutdown.Load() {
		hdl.mu.Unlock()
		cstr := C.CString(`{"result":"error","error":"handle is shutting down","code":503}`)
		C.call_response_cb(cb, cstr, userData)
		return
	}
	hdl.wg.Add(1)
	hdl.mu.Unlock()

	go func() {
		defer hdl.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error(fmt.Sprintf("LibwalletRequest goroutine panic: %v", r))
				if !hdl.shutdown.Load() {
					cstr := C.CString(fmt.Sprintf(`{"result":"error","error":%q,"code":500}`, fmt.Sprintf("panic: %v", r)))
					C.call_response_cb(cb, cstr, userData)
				}
			}
		}()

		var req struct {
			Path   string         `json:"path"`
			Verb   string         `json:"verb"`
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal([]byte(reqStr), &req); err != nil {
			if hdl.shutdown.Load() {
				return
			}
			cstr := C.CString(fmt.Sprintf(`{"result":"error","error":%q,"code":400}`, err.Error()))
			C.call_response_cb(cb, cstr, userData)
			return
		}
		if req.Verb == "" {
			req.Verb = "GET"
		}

		ctx := apirouter.New(context.Background(), req.Path, req.Verb)
		ctx.SetParams(req.Params)
		ctx.SetObject("@env", hdl.env)

		// Set response sink so progress updates go through the callback
		sink := &ffiSink{cb: cb, userData: userData, hdl: hdl}
		ctx.SetResponseSink(sink)

		resp, _ := ctx.Response()

		if hdl.shutdown.Load() {
			return // don't call back after shutdown
		}

		data, err := resp.MarshalJSON()
		if err != nil {
			if hdl.shutdown.Load() {
				return
			}
			cstr := C.CString(fmt.Sprintf(`{"result":"error","error":%q,"code":500}`, err.Error()))
			C.call_response_cb(cb, cstr, userData)
			return
		}
		cstr := C.CString(string(data))
		// Wipe the transient Go buffer that held the (possibly secret)
		// response payload now that it has been copied into the C string.
		zero(data)
		C.call_response_cb(cb, cstr, userData)
	}()
}

// LibwalletSetEventCallback registers a callback for server-pushed events
// (e.g., Web3 requests, online status). Events are forwarded from the
// internal BroadcastJson mechanism via a socketpair bridge.
// Pass nil cb to stop receiving events (closes the bridge and joins the
// reader goroutine). Re-registering replaces the previous bridge.
//
//export LibwalletSetEventCallback
func LibwalletSetEventCallback(h C.uintptr_t, cb C.event_callback, userData C.uintptr_t) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error(fmt.Sprintf("LibwalletSetEventCallback panic: %v", r))
		}
	}()

	hdl := loadHandle(h)
	if hdl == nil {
		return
	}

	// Serialize the whole event-bridge setup/teardown. This protects every
	// eventConn/eventDone read & write (previously raced across threads) and
	// serializes wg.Add against Destroy's wg.Wait.
	hdl.mu.Lock()
	defer hdl.mu.Unlock()

	// Tear down any existing bridge first. This makes a nil cb actually stop
	// delivery, and prevents re-registration from leaking the old FD plus a
	// goroutine blocked forever on Decode (which would hang Destroy's Wait).
	if hdl.eventConn != nil {
		hdl.eventConn.Close()
		hdl.eventConn = nil
		if hdl.eventDone != nil {
			<-hdl.eventDone // join the old reader goroutine before replacing it
			hdl.eventDone = nil
		}
	}

	// nil cb means "stop receiving events": the teardown above is all we do.
	if cb == nil {
		return
	}

	// Don't start new work once the handle is shutting down.
	if hdl.shutdown.Load() {
		return
	}

	// Create the event bridge (socketpair) lazily. One end is registered as a
	// jsonclient inside apirouter (receives BroadcastJson events), the other
	// end we read from.
	fd, err := apirouter.MakeJsonSocketFD(map[string]any{"@env": hdl.env})
	if err != nil {
		slog.Error(fmt.Sprintf("LibwalletSetEventCallback: failed to create event FD: %v", err))
		return
	}

	f := os.NewFile(uintptr(fd), "event-pipe")
	conn, err := net.FileConn(f)
	f.Close() // FileConn dups the FD
	if err != nil {
		slog.Error(fmt.Sprintf("LibwalletSetEventCallback: failed to wrap FD: %v", err))
		return
	}
	hdl.eventConn = conn

	done := make(chan struct{})
	hdl.eventDone = done

	hdl.wg.Add(1)
	go func() {
		defer close(done)
		defer hdl.wg.Done()
		defer conn.Close()
		defer func() {
			if r := recover(); r != nil {
				slog.Error(fmt.Sprintf("LibwalletSetEventCallback goroutine panic: %v", r))
			}
		}()

		dec := json.NewDecoder(conn)
		for {
			var msg json.RawMessage
			if err := dec.Decode(&msg); err != nil {
				return // connection closed — shutdown
			}
			if hdl.shutdown.Load() {
				return
			}
			cstr := C.CString(string(msg))
			// Wipe the transient Go buffer that held the event payload.
			zero(msg)
			C.call_event_cb(cb, cstr, userData)
		}
	}()
}

// LibwalletShowDebug enables debug logging on stderr.
//
// WARNING: this is process-global. It replaces the default slog handler for
// the entire host process (not just this handle) and debug-level logs may
// surface sensitive request detail (paths, params, errors) on stderr. It is
// intended for development only and should never be enabled in production.
// Per-handle scoping is not possible here because slog's default logger is a
// single process-wide global; scoping it would require threading a logger
// through every call site, which is out of scope for the FFI layer.
//
//export LibwalletShowDebug
func LibwalletShowDebug() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

// LibwalletDestroy cleans up the handle and closes the event bridge.
//
//export LibwalletDestroy
func LibwalletDestroy(h C.uintptr_t) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error(fmt.Sprintf("LibwalletDestroy panic: %v", r))
		}
	}()

	hdl := loadHandle(h)
	if hdl != nil {
		// Set shutdown flag and close the event bridge under the lock so it
		// is ordered against concurrent LibwalletRequest/SetEventCallback
		// (which take the same lock before any wg.Add). After this section no
		// new goroutine can be started, so the subsequent wg.Wait observes a
		// strictly happens-before, monotonically draining counter and can
		// never trip the "reused before previous Wait" panic.
		hdl.mu.Lock()
		hdl.shutdown.Store(true)
		if hdl.eventConn != nil {
			hdl.eventConn.Close()
			hdl.eventConn = nil
		}
		hdl.mu.Unlock()

		// Wait for all goroutines to finish so no callback fires after this
		// function returns and the C consumer tears down. Done outside the
		// lock so a late SetEventCallback teardown can't deadlock against it.
		hdl.wg.Wait()
	}
	deleteHandle(h)
}

// LibwalletFree frees a C string allocated by the library.
// Dart calls this to free response/event JSON strings.
//
// NOTE (audit M4): C strings returned to the consumer may contain secret
// material (mnemonics, keys). This frees the C heap allocation but does NOT
// zero it first, since LibwalletFree's existing contract is a plain
// counterpart to malloc and callers (Dart) rely on that. Zeroing-before-free
// would require either a separate length-tracking allocator on the Go side or
// a new dedicated export; that is flagged rather than changed here to avoid
// breaking the LibwalletFree contract. Transient Go-side secret buffers are
// already wiped (see zero() call sites) before the C string is handed out.
//
//export LibwalletFree
func LibwalletFree(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

func main() {}
