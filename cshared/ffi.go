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
	env     any // the wltbase environment
	eventFd int // FD from MakeJsonSocketFD for receiving broadcasts
}

var (
	handles   sync.Map // map[uintptr]*handle
	handleSeq atomic.Uintptr
)

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
}

func (f *ffiSink) SendResponse(r *apirouter.Response) error {
	data, err := r.MarshalJSON()
	if err != nil {
		return err
	}
	cstr := C.CString(string(data))
	C.call_response_cb(f.cb, cstr, f.userData)
	return nil
}

// LibwalletInit initializes the libwallet environment.
// Returns an opaque handle (>0) on success, 0 on failure.
//
//export LibwalletInit
func LibwalletInit(dataDir *C.char) C.uintptr_t {
	dir := C.GoString(dataDir)
	e, err := wltbase.InitEnv(dir)
	if err != nil {
		slog.Error(fmt.Sprintf("LibwalletInit failed: %v", err))
		return 0
	}

	// Create a socketpair via MakeJsonSocketFD. One end is registered as a
	// jsonclient inside apirouter (receives BroadcastJson events), the other
	// end (the returned FD) we read from to forward events to Dart.
	fd, err := apirouter.MakeJsonSocketFD(map[string]any{"@env": e})
	if err != nil {
		slog.Error(fmt.Sprintf("LibwalletInit: failed to create event FD: %v", err))
		return 0
	}

	h := &handle{env: e, eventFd: fd}
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
	hdl := loadHandle(h)
	if hdl == nil {
		cstr := C.CString(`{"result":"error","error":"invalid handle","code":500}`)
		C.call_response_cb(cb, cstr, userData)
		return
	}

	reqStr := C.GoString(requestJson)

	go func() {
		var req struct {
			Path   string         `json:"path"`
			Verb   string         `json:"verb"`
			Params map[string]any `json:"params"`
		}
		if err := json.Unmarshal([]byte(reqStr), &req); err != nil {
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
		sink := &ffiSink{cb: cb, userData: userData}
		ctx.SetResponseSink(sink)

		resp, _ := ctx.Response()

		data, err := resp.MarshalJSON()
		if err != nil {
			cstr := C.CString(fmt.Sprintf(`{"result":"error","error":%q,"code":500}`, err.Error()))
			C.call_response_cb(cb, cstr, userData)
			return
		}
		cstr := C.CString(string(data))
		C.call_response_cb(cb, cstr, userData)
	}()
}

// LibwalletSetEventCallback registers a callback for server-pushed events
// (e.g., Web3 requests, online status). Events are forwarded from the
// internal BroadcastJson mechanism via a socketpair bridge.
// Pass nil cb to stop receiving events.
//
//export LibwalletSetEventCallback
func LibwalletSetEventCallback(h C.uintptr_t, cb C.event_callback, userData C.uintptr_t) {
	hdl := loadHandle(h)
	if hdl == nil || cb == nil {
		return
	}

	// Read from the event FD (our end of the socketpair from MakeJsonSocketFD).
	// The jsonclient on the other end receives all BroadcastJson events and
	// writes them as newline-delimited JSON.
	go func() {
		f := os.NewFile(uintptr(hdl.eventFd), "event-pipe")
		conn, err := net.FileConn(f)
		f.Close() // FileConn dups the FD, so we close the File
		if err != nil {
			slog.Error(fmt.Sprintf("LibwalletSetEventCallback: failed to wrap FD: %v", err))
			return
		}
		defer conn.Close()

		dec := json.NewDecoder(conn)
		for {
			var msg json.RawMessage
			if err := dec.Decode(&msg); err != nil {
				return // connection closed
			}
			cstr := C.CString(string(msg))
			C.call_event_cb(cb, cstr, userData)
		}
	}()
}

// LibwalletShowDebug enables debug logging on stderr.
//
//export LibwalletShowDebug
func LibwalletShowDebug() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

// LibwalletDestroy cleans up the handle and closes the event bridge.
//
//export LibwalletDestroy
func LibwalletDestroy(h C.uintptr_t) {
	hdl := loadHandle(h)
	if hdl != nil && hdl.eventFd > 0 {
		// Closing the FD terminates the event reader goroutine
		f := os.NewFile(uintptr(hdl.eventFd), "event-pipe-close")
		f.Close()
	}
	deleteHandle(h)
}

// LibwalletFree frees a C string allocated by the library.
// Dart calls this to free response/event JSON strings.
//
//export LibwalletFree
func LibwalletFree(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

func main() {}
