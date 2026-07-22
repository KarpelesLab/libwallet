#!/bin/make
# libwallet build — Rust backend (cdylib/staticlib FFI) consumed by the Dart
# client under dart/. The Go implementation was removed; the crate lives in
# rust/ and exposes the same C ABI (LibwalletInit/Request/… ) the Dart FFI and
# the iOS/Android bridges load.

GIT_TAG := $(shell git rev-parse --short HEAD)
ifeq ($(DATE_TAG),)
DATE_TAG := $(shell TZ=UTC git show -s --format=%cd --date=format-local:%Y%m%d%H%M%S HEAD)
endif
# When HEAD is exactly a v* tag, capture it (leading "v" stripped) as the
# release version — handlers/info.rs reads it to differentiate release vs dev
# binaries, the same signal the old Go -ldflags -X injection carried.
TAG_VERSION := $(shell git describe --exact-match --tags --match 'v*' 2>/dev/null | sed 's/^v//')

# Baked into the FFI lib at compile time via option_env! (handlers/info.rs).
export LIBWALLET_GIT_TAG := $(GIT_TAG)
export LIBWALLET_DATE_TAG := $(DATE_TAG)
export LIBWALLET_VERSION := $(TAG_VERSION)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
DYLIB_EXT := dylib
else
DYLIB_EXT := so
endif

.PHONY: all build test deps fmt clean dart-native

all: build

build:
	cd rust && cargo build --release

test:
	cd rust && cargo test

deps:
	cd rust && cargo fetch

fmt:
	cd rust && cargo fmt

# Build the FFI cdylib for the current desktop platform and stage it where the
# Dart client's local-dev path looks for it: hook/build.dart prefers
# dart/testserver/liblibwallet.<ext> over downloading a release binary.
dart-native: build
	mkdir -p dart/testserver
	cp rust/target/release/liblibwallet.$(DYLIB_EXT) dart/testserver/liblibwallet.$(DYLIB_EXT)

clean:
	cd rust && cargo clean
	$(RM) dart/testserver/liblibwallet.*
