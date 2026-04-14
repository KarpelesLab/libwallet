// Native asset build hook for libwallet.
//
// Downloads pre-built platform binaries from the matching GitHub Release.
// The release version matches the Dart package version from pubspec.yaml.

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

const _repo = 'KarpelesLab/libwallet';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;

    final codeConfig = input.config.code;
    final os = codeConfig.targetOS;
    final arch = codeConfig.targetArchitecture;

    // Map Dart OS/arch names to our binary naming convention
    String dartName;
    String ext;
    LinkMode linkMode;

    switch (os) {
      case OS.macOS:
        dartName = 'macos-${_archName(arch)}';
        ext = 'dylib';
        linkMode = DynamicLoadingBundled();
      case OS.linux:
        dartName = 'linux-${_archName(arch)}';
        ext = 'so';
        linkMode = DynamicLoadingBundled();
      case OS.android:
        dartName = 'android-${_archName(arch)}';
        ext = 'so';
        linkMode = DynamicLoadingBundled();
      case OS.iOS:
        // Distinguish iOS device (iphoneos) from simulator (iphonesimulator).
        // The binaries are NOT interchangeable: simulator builds link against
        // different frameworks than on-device builds.
        final iosSdk = codeConfig.iOS.targetSdk;
        final prefix = iosSdk == IOSSdk.iPhoneSimulator ? 'iossimulator' : 'ios';
        dartName = '$prefix-${_archName(arch)}';
        ext = 'a';
        linkMode = LookupInProcess();
      case OS.windows:
        dartName = 'windows-${_archName(arch)}';
        ext = 'dll';
        linkMode = DynamicLoadingBundled();
      default:
        return;
    }

    final fileName = 'liblibwallet-$dartName.$ext';

    // 1. Prefer a local dev binary at testserver/liblibwallet.<ext>
    //    (built via `go build -buildmode=c-shared` during development).
    final localFile =
        input.packageRoot.resolve('testserver/liblibwallet.$ext');
    if (File.fromUri(localFile).existsSync()) {
      output.assets.code.add(
        CodeAsset(
          package: input.packageName,
          name: 'liblibwallet',
          linkMode: linkMode,
          file: localFile,
        ),
      );
      return;
    }

    // 2. Otherwise, check the shared output cache
    final outputDir = input.outputDirectoryShared;
    final cachedFile = outputDir.resolve(fileName);

    if (!File.fromUri(cachedFile).existsSync()) {
      // Read the package version from pubspec.yaml
      final pubspecFile = File.fromUri(input.packageRoot.resolve('pubspec.yaml'));
      final pubspecContent = await pubspecFile.readAsString();
      final versionMatch = RegExp(r'version:\s*(\S+)').firstMatch(pubspecContent);
      final version = versionMatch?.group(1) ?? '0.0.0';
      final url = Uri.parse(
        'https://github.com/$_repo/releases/download/v$version/$fileName',
      );

      stderr.writeln('Downloading $url ...');

      final httpClient = HttpClient();
      try {
        final request = await httpClient.getUrl(url);
        final response = await request.close();

        if (response.statusCode == 200) {
          final file = File.fromUri(cachedFile);
          await file.create(recursive: true);
          await response.pipe(file.openWrite());
          stderr.writeln('Downloaded $fileName (${file.lengthSync()} bytes)');
        } else if (response.statusCode == 404) {
          stderr.writeln(
            'WARNING: $fileName not found for v$version. '
            'Build the Go library manually or ensure the release has this asset.',
          );
          await response.drain<void>();
          return;
        } else {
          stderr.writeln(
            'WARNING: Failed to download $fileName: HTTP ${response.statusCode}',
          );
          await response.drain<void>();
          return;
        }
      } finally {
        httpClient.close();
      }
    }

    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: 'liblibwallet',
        linkMode: linkMode,
        file: cachedFile,
      ),
    );
  });
}

String _archName(Architecture? arch) {
  switch (arch) {
    case Architecture.arm64:
      return 'arm64';
    case Architecture.x64:
      return 'x64';
    case Architecture.arm:
      return 'arm';
    case Architecture.ia32:
      return 'x86';
    default:
      return arch.toString();
  }
}
