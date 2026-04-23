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
  # right slice for the active SDK at build time and copies it into
  # $(PODS_XCFRAMEWORKS_BUILD_DIR)/libwallet/libwallet.a, then
  # adds the appropriate -L / -l flags automatically. No more
  # per-SDK conditionals, no more wrong-SDK "ignoring file" warning.
  s.ios.vendored_frameworks = 'libwallet.xcframework'

  # Two flags are needed to make dlsym work on iOS release builds:
  #
  # 1. -force_load pulls all object files from the static archive
  #    into the binary — without it the linker dead-strips every
  #    symbol the FFI entry points transitively depend on, since
  #    nothing in C statically references them.
  #
  # 2. -exported_symbol _Libwallet* keeps those specific symbols
  #    in the final binary's export trie. Release Xcode builds
  #    drop the export trie for unreferenced symbols as part of
  #    dead-code elimination, even when the code itself survives
  #    via -force_load — dlsym(RTLD_DEFAULT, ...) searches the
  #    export trie, not the full symbol table, so the code is
  #    present but invisible. Debug builds work because the debug
  #    dylib is linked with -rdynamic which exports everything.
  #
  # We want to point -force_load at
  # $(PODS_XCFRAMEWORKS_BUILD_DIR)/libwallet/libwallet.a (where
  # CocoaPods' [CP] Copy XCFrameworks phase places the active
  # slice), but Xcode validates link-phase input files before
  # respecting cross-target build order — Runner's link sees the
  # path as missing because Pods_Runner's Copy XCFrameworks phase
  # hasn't run yet at validation time.
  #
  # Workaround: reach into the xcframework's source location, where
  # the slice already exists (prepare_command above wrote it there).
  # That brings back per-SDK conditionals because xcframework slices
  # are named after their SDK+arch combination — but the paths are
  # stable and present from pod install onward.
  xcframework_slice_device = '"$(PODS_ROOT)/../.symlinks/plugins/libwallet/ios/libwallet.xcframework/ios-arm64/libwallet.a"'
  xcframework_slice_sim    = '"$(PODS_ROOT)/../.symlinks/plugins/libwallet/ios/libwallet.xcframework/ios-arm64_x86_64-simulator/libwallet.a"'

  # Every FFI entry point declared with `//export` in cshared/ffi.go.
  # Keep in sync with that file — if new exports are added there,
  # they must be listed here too or dlsym will silently fail to find
  # them on iOS release builds.
  ffi_exports = %w[
    _LibwalletInit
    _LibwalletRequest
    _LibwalletSetEventCallback
    _LibwalletShowDebug
    _LibwalletDestroy
    _LibwalletFree
  ]
  ffi_export_flags = ffi_exports.map { |sym| "-Xlinker -exported_symbol -Xlinker #{sym}" }.join(' ')

  s.user_target_xcconfig = {
    'OTHER_LDFLAGS[sdk=iphoneos*]' =>
      "$(inherited) -force_load #{xcframework_slice_device} #{ffi_export_flags}",
    'OTHER_LDFLAGS[sdk=iphonesimulator*]' =>
      "$(inherited) -force_load #{xcframework_slice_sim} #{ffi_export_flags}",
  }

  # Go runtime needs CoreFoundation + Security for entropy /
  # keychain hooks, and resolv for the chain RPC HTTP client's
  # DNS lookups.
  s.frameworks = 'CoreFoundation', 'Security'
  s.libraries  = 'resolv'
end
