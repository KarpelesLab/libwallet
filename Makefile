#!/bin/make
GOROOT:=$(shell PATH="/pkg/main/dev-lang.go.dev/bin:$$PATH" go env GOROOT)
GOPATH:=$(shell $(GOROOT)/bin/go env GOPATH)
GOOS:=$(shell $(GOROOT)/bin/go env GOOS)
GIT_TAG:=$(shell git rev-parse --short HEAD)
SOURCES:=$(shell find . -name '*.go' -o -name '*.h' -o -name '*.m')
ifeq ($(DATE_TAG),)
DATE_TAG:=$(shell TZ=UTC git show -s --format=%cd --date=format-local:%Y%m%d%H%M%S HEAD)
endif

DIST_FILES=dist/android/libwallet.aar

ifeq ($(GOOS),darwin)
# if on mac
DIST_FILES:=$(DIST_FILES) dist/ios/Libwallet.xcframework
endif

GOFLAGS=-ldflags=all="-X main.dateTag=$(DATE_TAG) -X main.gitTag=$(GIT_TAG)"

.PHONY: ios android dist test deps dart-native dart-native-macos dart-native-linux

all:
	$(GOPATH)/bin/goimports -w -l .
	$(GOROOT)/bin/go build -v $(GOFLAGS)

deps:
	$(GOROOT)/bin/go get -v -t .

test:
	$(GOROOT)/bin/go test -v -count=1 -p 1 ./...

$(GOPATH)/bin/restupload:
	$(GOROOT)/bin/go install github.com/KarpelesLab/rest/cli/restupload@latest

dist: libwallet-$(DATE_TAG)-$(GIT_TAG).tar.gz $(GOPATH)/bin/restupload
ifeq ($(GOOS),darwin)
	# only macos version has the full build, so only distribute that one
	$(GOPATH)/bin/restupload -api Cloud/MobileLib/libwallet:upload -params 'filename=$<&version=$(DATE_TAG)-$(GIT_TAG)' $<
	play -n synth pl G2 pl B2 pl D3 pl G3 pl D4 pl G4 delay 0 .05 .1 .15 .2 .25 remix - fade 0 4 .1 norm -1 || true
endif

libwallet-$(DATE_TAG)-$(GIT_TAG).tar.gz: $(DIST_FILES)
	tar czf $@ dist api.md

ios: dist/ios/Libwallet.xcframework

dist/ios/Libwallet.xcframework: $(SOURCES)
	mkdir -p dist/ios
	PATH="$(GOPATH)/bin:$$PATH" gomobile bind -v --target ios,iossimulator -o $@ $(GOFLAGS)

android: dist/android/libwallet.aar

libwallet-sources.jar: libwallet.aar

dist/android/libwallet.aar: $(SOURCES)
	mkdir -p dist/android
ifeq ($(GOOS),darwin)
	PATH="$(GOPATH)/bin:$$PATH" JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' gomobile bind -v -target android -androidapi 21 -javapkg com.karpeleslabs.libwallet -o "$@" $(GOFLAGS)
else
	PATH="$(GOPATH)/bin:$$PATH" gomobile bind -v -target android -androidapi 21 -javapkg com.karpeleslabs.libwallet -o "$@" $(GOFLAGS)
endif

# Build c-shared library for Dart FFI (current platform)
dart-native:
	CGO_ENABLED=1 $(GOROOT)/bin/go build -buildmode=c-shared $(GOFLAGS) -o dart/testserver/liblibwallet.dylib ./cshared/

# Build c-shared libraries for all macOS architectures
dart-native-macos:
	mkdir -p dart/native/macos-arm64 dart/native/macos-x64
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 $(GOROOT)/bin/go build -buildmode=c-shared $(GOFLAGS) -o dart/native/macos-arm64/liblibwallet.dylib ./cshared/
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 $(GOROOT)/bin/go build -buildmode=c-shared $(GOFLAGS) -o dart/native/macos-x64/liblibwallet.dylib ./cshared/

# Build c-shared libraries for all Linux architectures
dart-native-linux:
	mkdir -p dart/native/linux-arm64 dart/native/linux-x64
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 $(GOROOT)/bin/go build -buildmode=c-shared $(GOFLAGS) -o dart/native/linux-arm64/liblibwallet.so ./cshared/
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GOROOT)/bin/go build -buildmode=c-shared $(GOFLAGS) -o dart/native/linux-x64/liblibwallet.so ./cshared/

clean:
	PATH="$(GOPATH)/bin:$$PATH" gomobile clean
	$(RM) -r dist libwallet.xcframework libwallet.aar libwallet-sources.jar libwallet-*.tar.gz
	$(RM) -r dart/native dart/testserver/liblibwallet.* dart/testserver/testserver
