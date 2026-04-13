// Native asset build hook for libwallet.
// Declares pre-built platform binaries so Dart/Flutter can bundle them.
//
// Pre-built binaries are expected in native/<os>-<arch>/ directories.
// Build these with: make -C .. dart-native-macos (or dart-native-linux)
//
// If the binary doesn't exist for the target platform, no asset is declared
// and the user must load the library manually or use the socket transport.

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;

    final codeConfig = input.config.code;
    final os = codeConfig.targetOS;
    final arch = codeConfig.targetArchitecture;

    // Determine file extension based on platform
    String ext;
    LinkMode linkMode;
    switch (os) {
      case OS.macOS:
        ext = 'dylib';
        linkMode = DynamicLoadingBundled();
      case OS.linux:
      case OS.android:
        ext = 'so';
        linkMode = DynamicLoadingBundled();
      case OS.iOS:
        ext = 'a';
        linkMode = LookupInProcess();
      case OS.windows:
        ext = 'dll';
        linkMode = DynamicLoadingBundled();
      default:
        return;
    }

    final nativePath = 'native/$os-$arch/liblibwallet.$ext';
    final file = input.packageRoot.resolve(nativePath);

    // Only declare the asset if the binary actually exists
    if (!File.fromUri(file).existsSync()) return;

    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: 'liblibwallet',
        linkMode: linkMode,
        file: file,
      ),
    );
  });
}
