#
# CocoaPods spec for the libwallet Dart FFI plugin (iOS).
#
# Why this exists: Dart's `code_assets` build hook produces a
# `CodeAsset(linkMode: LookupInProcess())` for the iOS `.a` static
# archive, but the Flutter iOS build pipeline does not reliably
# pass static archives from code_assets through to Xcode's linker.
# The result is a runtime `dlsym` failure ("symbol not found:
# LibwalletInit") on `flutter run` for any external app.
#
# This podspec is the explicit linker integration. Flutter picks
# it up automatically because the package's pubspec.yaml declares
# `flutter.plugin.platforms.ios.ffiPlugin: true`. At pod install
# time we download the per-SDK static archives from the matching
# GitHub Release, lipo the simulator slices together, then wrap
# everything into a `libwallet.xcframework` via xcodebuild
# -create-xcframework. CocoaPods knows how to handle xcframeworks
# (it picks the right slice for the active SDK at build time),
# which is Apple's recommended binary-distribution format and
# eliminates the per-SDK link-time hacks the older vendored_
# libraries approach required.
#
# We still need `-force_load` because every libwallet entry point
# is resolved via dlsym from Dart, never statically referenced
# from C, so without -force_load the linker dead-strips the whole
# archive on dead-code elimination. The path is uniform across
# SDKs because CocoaPods extracts the active xcframework slice
# into a per-build-config dir (PODS_XCFRAMEWORKS_BUILD_DIR), so
# OTHER_LDFLAGS no longer needs sdk-conditional variants.
#

require 'yaml'

# Resolve the matching libwallet release version from this Dart
# package's pubspec.yaml. Done in Ruby so the URL stays in lock-
# step with whatever version pub.dev resolved — pinning the
# version in the podspec itself would silently desync.
pubspec_path = File.expand_path('../pubspec.yaml', __dir__)
pubspec = YAML.load_file(pubspec_path)
package_version = pubspec.fetch('version', '0.0.0').to_s

Pod::Spec.new do |s|
  s.name             = 'libwallet'
  s.version          = package_version
  s.summary          = 'libwallet Go FFI runtime (multi-chain TSS wallet).'
  s.description      = <<-DESC
                        Static-archive integration for the libwallet
                        Dart FFI plugin. Downloads per-SDK iOS
                        archives from the matching GitHub Release at
                        pod install time and force-loads them into
                        the host app so dlsym can resolve the
                        Libwallet* C entry points at runtime.
                       DESC
  s.homepage         = 'https://github.com/KarpelesLab/libwallet'
  s.license          = { :type => 'Proprietary' }
  s.author           = 'Karpeles Lab Inc'
  s.source           = { :path => '.' }
  s.ios.deployment_target = '13.0'

  # Compile the Objective-C bridge into the libwallet pod target.
  # The bridge gives the linker a real static reference from app
  # source code to each Go-exported FFI symbol, which is what
  # makes them survive into the host binary's export trie under
  # default visibility — see Classes/LibwalletBridge.m for the
  # full rationale. Required for dart:ffi's dlsym lookups to
  # work on iOS release builds.
  s.source_files = 'Classes/**/*.{m,h}'
  s.requires_arc = true

  # Skip downloads when a pre-built .a is already present in the
  # pod source dir (CI / local-dev path). Otherwise pull from the
  # matching GitHub Release. The fat simulator archive is built
  # locally via lipo, then everything gets wrapped into an
  # .xcframework via xcodebuild — that's the format vendored_
  # frameworks below expects and the standard Apple-blessed
  # binary-distribution shape.
  s.prepare_command = <<-CMD
    set -e
    base="https://github.com/KarpelesLab/libwallet/releases/download/v#{package_version}"

    fetch() {
      file="$1"
      if [ -f "$file" ]; then
        echo "[libwallet pod] reusing local $file"
        return
      fi
      echo "[libwallet pod] downloading $file from $base"
      curl --fail --silent --show-error --location \
           --output "$file" "$base/$file"
    }

    fetch liblibwallet-ios-arm64.a

    # CI / local-dev path: a pre-built fat simulator archive sitting in
    # the pod dir short-circuits both slice downloads and the lipo step.
    # On end-user `flutter run` the file is absent — fetch both per-arch
    # slices from the matching release and lipo them together.
    if [ ! -f liblibwallet-iossimulator.a ]; then
      fetch liblibwallet-iossimulator-arm64.a
      fetch liblibwallet-iossimulator-x64.a
      echo "[libwallet pod] lipo'ing simulator slices"
      lipo -create \
        liblibwallet-iossimulator-arm64.a \
        liblibwallet-iossimulator-x64.a \
        -output liblibwallet-iossimulator.a
    fi

    # Stage the per-SDK archives with a uniform basename so the
    # generated xcframework's slices both contain `libwallet.a` —
    # then OTHER_LDFLAGS below can reference a single fixed path
    # regardless of the active SDK.
    if [ ! -d libwallet.xcframework ]; then
      echo "[libwallet pod] building libwallet.xcframework"
      stage="$(mktemp -d)"
      mkdir -p "$stage/device" "$stage/sim" "$stage/headers"
      cp liblibwallet-ios-arm64.a "$stage/device/libwallet.a"
      cp liblibwallet-iossimulator.a "$stage/sim/libwallet.a"
      xcodebuild -create-xcframework \
        -library "$stage/device/libwallet.a" -headers "$stage/headers" \
        -library "$stage/sim/libwallet.a"    -headers "$stage/headers" \
        -output libwallet.xcframework
      rm -rf "$stage"
    fi
  CMD

  # vendored_frameworks with an .xcframework: CocoaPods picks the
  # right slice for the active SDK at build time. The slice is a
  # static .a; CocoaPods links it into the libwallet pod's
  # dynamic framework (use_frameworks! default) so the Go runtime
  # and all libwallet entry points end up inside libwallet.framework's
  # binary, in exactly one place. Runner does NOT need a separate
  # -force_load of the same .a — see the long history block in the
  # pod_target_xcconfig comment below.
  s.ios.vendored_frameworks = 'libwallet.xcframework'

  # Why this pod target's xcconfig overrides instead of
  # user_target_xcconfig:
  #
  # Until 0.4.42 we shipped a `-force_load` of the xcframework
  # slice via user_target_xcconfig — i.e. we asked Xcode to
  # statically link the libwallet .a into the host Runner binary.
  # CocoaPods (with the standard Flutter use_frameworks! Podfile)
  # SEPARATELY wraps this pod into a dynamic libwallet.framework
  # dylib that ALSO contains the same .a. End result: Go runtime
  # gets initialised twice in the same process. The two runtimes
  # fight for signal-handler ownership and SIGABRT inside
  # `runtime.raise_trampoline.abi0` on a worker thread (reported
  # as a recurring TestFlight crash on net.tibane.tibaneapp).
  #
  # Fix: stop linking libwallet.a into Runner. The dynamic
  # framework already has it; dlsym(RTLD_DEFAULT, libwallet_init)
  # walks every loaded image and finds the bridge symbol in
  # libwallet.framework's export trie. No -force_load on Runner
  # = no second Go runtime.
  #
  # We still need to keep the bridge symbols from being
  # dead-stripped when the framework links. The bridge functions
  # in Classes/LibwalletBridge.m call into Libwallet* (statically
  # referenced from C), which provides linker roots for the
  # underlying Go symbols. `__attribute__((used,
  # visibility("default")))` on each bridge function ensures the
  # bridge itself stays kept and exported with default visibility.
  # `GCC_SYMBOLS_PRIVATE_EXTERN = NO` here is the pod-wide
  # backstop in case anyone adds another .m later and forgets
  # the per-symbol attribute.
  s.pod_target_xcconfig = {
    'GCC_SYMBOLS_PRIVATE_EXTERN' => 'NO',
  }

  # Go runtime needs CoreFoundation + Security for entropy /
  # keychain hooks, and resolv for the chain RPC HTTP client's
  # DNS lookups.
  s.frameworks = 'CoreFoundation', 'Security'
  s.libraries  = 'resolv'
end
