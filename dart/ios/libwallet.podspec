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
# GitHub Release (so the `.pub-cache` doesn't carry tens of MB of
# binaries), then `-force_load` them into the host app target so
# the FFI symbols survive the linker's dead-strip pass.
#
# Both device + simulator slices are downloaded and combined into
# a single fat simulator `.a` via `lipo`; the per-SDK xcconfig
# below picks the correct one for each Xcode build configuration.
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
  # locally via lipo to keep the per-SDK xcconfig below simple.
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
  CMD

  # Both archives are listed under vendored_libraries so CocoaPods
  # actually copies them into $(PODS_ROOT)/libwallet/ (preserve_paths
  # alone doesn't copy for path-based pods, only for remote sources).
  # vendored_libraries auto-emits `-llibwallet-ios-arm64 -llibwallet-iossimulator`
  # on every link line — for the wrong-SDK slice the linker prints a
  # benign "ignoring file ... built for iOS / iOS Simulator" warning
  # and skips it, which is harmless. The per-SDK -force_load below is
  # what actually pulls the FFI symbols in for the matching SDK.
  s.ios.vendored_libraries =
    'liblibwallet-ios-arm64.a',
    'liblibwallet-iossimulator.a'

  # The -force_load path has to point at where the .a actually lives
  # in the consumer app's project, which is NOT PODS_ROOT/libwallet/
  # for an ffiPlugin path-based pod — Flutter symlinks the plugin
  # under <app>/ios/.symlinks/plugins/libwallet/ and CocoaPods does
  # not copy vendored_libraries into PODS_ROOT/<pod>/ from there. The
  # -L<symlinks/...> path is added automatically by CocoaPods (see
  # the auto-emitted -llibwallet-ios-arm64 / -llibwallet-iossimulator
  # flags), so the bare -l link works; force_load needs the explicit
  # full path though, so reach into .symlinks/ via $(PODS_ROOT)/../.
  s.user_target_xcconfig = {
    'OTHER_LDFLAGS[sdk=iphoneos*]' =>
      '$(inherited) -force_load "$(PODS_ROOT)/../.symlinks/plugins/libwallet/ios/liblibwallet-ios-arm64.a"',
    'OTHER_LDFLAGS[sdk=iphonesimulator*]' =>
      '$(inherited) -force_load "$(PODS_ROOT)/../.symlinks/plugins/libwallet/ios/liblibwallet-iossimulator.a"',
  }

  # Go runtime needs CoreFoundation + Security for entropy /
  # keychain hooks, and resolv for the chain RPC HTTP client's
  # DNS lookups.
  s.frameworks = 'CoreFoundation', 'Security'
  s.libraries  = 'resolv'
end
