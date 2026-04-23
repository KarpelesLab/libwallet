// Package wltlog is libwallet's leveled-log facade. Callers use
// Debugf / Infof / Warnf / Errorf exactly like log.Printf; output only
// reaches the underlying logger when the runtime level is at least the
// call's level.
//
// # Controlling the level
//
// The host wallet app sets the level once at startup via
// Info:setWalletInfo's LogLevel field. An empty LogLevel means
// "auto" — libwallet picks a sensible default for the build type:
//
//   - release binaries (when version is set via -ldflags at build
//     time): "info" — only routine state changes and errors. No
//     per-RPC or per-sign chatter.
//   - dev binaries (version empty): "debug" — everything, useful
//     when reproducing a user-reported issue locally.
//
// Valid values (case-insensitive): "debug", "info", "warn", "error",
// "off". Anything else is treated as "info". No panics, ever, from
// the log path.
//
// # Why not log/slog?
//
// log/slog is great for structured logging, but libwallet runs inside
// a c-shared library linked into a mobile app. The host's logger
// (logcat on Android, NSLog on iOS via stderr redirect) doesn't care
// about JSON or attributes — it wants one human-readable line per
// event. log.Printf is the right granularity, and keeping all log
// call sites on a single helper is what makes "flip a switch to see
// everything" cheap.
package wltlog

import (
	"fmt"
	"log"
	"strings"
	"sync/atomic"
)

// Level controls which calls actually emit. Ordering:
//
//	LevelOff < LevelError < LevelWarn < LevelInfo < LevelDebug
//
// A call at level L emits when the current runtime level is >= L.
type Level int32

const (
	// LevelOff disables every call site. Useful for release binaries
	// where the host wallet redirects stderr somewhere sensitive.
	LevelOff Level = iota
	// LevelError logs only unrecoverable conditions that the user
	// will feel (sign failure, broadcast rejection).
	LevelError
	// LevelWarn logs conditions that self-heal or have a fallback
	// (stale pubkey detected and repaired, RPC retry).
	LevelWarn
	// LevelInfo is the default. One line per meaningful state
	// change: wallet loaded, account selected, tx broadcast.
	LevelInfo
	// LevelDebug adds per-operation detail: RPC method+latency,
	// intermediate state dumps, "why did this gate skip" messages.
	// Expect 10-50x the volume of Info.
	LevelDebug
)

// currentLevel is a package-global atomic so helpers don't take a
// lock on the hot path. Default zero value is LevelOff — the package
// init picks a build-appropriate default at startup.
var currentLevel atomic.Int32

// autoDefault is the level picked when LogLevel is empty. Overridden
// by wltbase at package init time based on whether gitTag is set.
var autoDefault atomic.Int32

// output is a host-supplied sink. On Flutter+iOS the Go runtime's
// os.Stderr doesn't reach the Dart-side logger, so every visible
// log line has to flow through the callback channel the host has
// already wired up for events. wltbase registers such a sink in
// its init; tests and CLI builds leave it nil and get log.Printf.
type Sink func(level Level, line string)

var output atomic.Pointer[Sink]

func init() {
	// Safe initial default until wltbase (or a test) bumps it.
	currentLevel.Store(int32(LevelInfo))
	autoDefault.Store(int32(LevelInfo))
}

// SetAutoDefault changes what "" resolves to. Called once at startup
// by wltbase, using version presence as the signal for release vs dev.
// Passing LevelOff disables auto-logging in release builds; passing
// LevelDebug makes a dev build chatty out of the box.
func SetAutoDefault(l Level) {
	autoDefault.Store(int32(l))
	// If nobody has explicitly set a level yet (currentLevel is at
	// the prior auto-default), follow the new one. We can't
	// distinguish "user set info" from "auto set info" here — tiny
	// wart: a host that explicitly picks the current auto-default
	// before SetAutoDefault runs loses its pick. Acceptable given
	// SetAutoDefault is called exactly once from wltbase.init.
	currentLevel.Store(int32(l))
}

// SetLevelString parses name and updates the runtime level. An empty
// string resolves to the auto default (see SetAutoDefault). Unknown
// names fall back to LevelInfo rather than failing — a typo in the
// host app shouldn't silence logs.
func SetLevelString(name string) Level {
	l := parseLevel(name)
	currentLevel.Store(int32(l))
	return l
}

// GetLevel returns the current runtime level.
func GetLevel() Level {
	return Level(currentLevel.Load())
}

// String returns the canonical name for a Level. Used by
// Info:getWalletInfo so hosts can echo back what libwallet thinks
// the level is.
func (l Level) String() string {
	switch l {
	case LevelOff:
		return "off"
	case LevelError:
		return "error"
	case LevelWarn:
		return "warn"
	case LevelInfo:
		return "info"
	case LevelDebug:
		return "debug"
	default:
		return "info"
	}
}

func parseLevel(name string) Level {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "":
		return Level(autoDefault.Load())
	case "off", "none", "silent":
		return LevelOff
	case "error", "err":
		return LevelError
	case "warn", "warning":
		return LevelWarn
	case "info":
		return LevelInfo
	case "debug", "trace", "verbose":
		return LevelDebug
	default:
		return LevelInfo
	}
}

// Enabled reports whether a call at the given level would emit. Use
// this to guard expensive argument formatting (e.g. hex-encoding a
// large buffer) behind a level check before calling Debugf/Infof.
func Enabled(l Level) bool {
	return Level(currentLevel.Load()) >= l
}

// SetSink installs a host-side log sink. wltbase calls this from its
// init() with a function that forwards every line to the apirouter
// broadcast channel, so the Dart side receives them as "log" events
// and can route them to `developer.log`. Pass nil to fall back to the
// stderr default (useful for tests).
func SetSink(fn Sink) {
	if fn == nil {
		output.Store(nil)
		return
	}
	output.Store(&fn)
}

// emit writes one log line. When a sink is installed the stderr
// log.Printf path is skipped — not because the sink is untrusted but
// because on Flutter+iOS log.Printf goes nowhere readable anyway, and
// on Android it would double-log. Tests (no sink) keep the stderr
// output they rely on.
//
// A panic inside the sink is swallowed and falls back to stderr so a
// broken logging pipeline can never take down a user's send.
func emit(level Level, format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	if p := output.Load(); p != nil {
		delivered := false
		func() {
			defer func() {
				_ = recover()
			}()
			(*p)(level, line)
			delivered = true
		}()
		if delivered {
			return
		}
	}
	log.Printf("[%s] %s", level, line)
}

// Debugf logs at LevelDebug. Format is a Printf-style template; the
// output is prefixed with "[debug] " so callers can grep by level
// regardless of the host's logger format.
func Debugf(format string, args ...any) {
	if Enabled(LevelDebug) {
		emit(LevelDebug, format, args...)
	}
}

// Infof logs at LevelInfo.
func Infof(format string, args ...any) {
	if Enabled(LevelInfo) {
		emit(LevelInfo, format, args...)
	}
}

// Warnf logs at LevelWarn.
func Warnf(format string, args ...any) {
	if Enabled(LevelWarn) {
		emit(LevelWarn, format, args...)
	}
}

// Errorf logs at LevelError. NOT a fatal — callers still return
// errors to the user. This is only the log side.
func Errorf(format string, args ...any) {
	if Enabled(LevelError) {
		emit(LevelError, format, args...)
	}
}
