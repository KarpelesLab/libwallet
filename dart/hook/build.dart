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
        // iOS is handled by `ios/libwallet.podspec` (Flutter FFI plugin
        // auto-include). The build hook would emit a `LookupInProcess` code
        // asset for the .a archive, but Flutter's iOS pipeline does not
        // reliably link static archives from code_assets through to Xcode —
        // the symbols get dead-stripped and dlsym fails at runtime. The
        // podspec's per-SDK `-force_load` is the working path. Returning
        // here means the hook emits no iOS asset and the podspec is the
        // sole source of truth for iOS linking.
        return;
      case OS.windows:
        dartName = 'windows-${_archName(arch)}';
        ext = 'dll';
        linkMode = DynamicLoadingBundled();
      default:
        return;
    }

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

    // 2. Otherwise, check the shared output cache.
    //
    // The cached filename embeds the package version so that bumping
    // the Dart package forces a re-download of the matching binary.
    // Without the version stamp, a previously cached file (e.g. from
    // 0.3.23) silently keeps serving stale code after `dart pub upgrade`
    // — root cause of the "events arriving with pre-unification type
    // strings" class of bugs.
    final pubspecFile = File.fromUri(input.packageRoot.resolve('pubspec.yaml'));
    final pubspecContent = await pubspecFile.readAsString();
    final versionMatch = RegExp(r'version:\s*(\S+)').firstMatch(pubspecContent);
    final version = versionMatch?.group(1) ?? '0.0.0';

    final remoteName = 'liblibwallet-$dartName.$ext';
    final cachedName = 'liblibwallet-$dartName-v$version.$ext';
    final outputDir = input.outputDirectoryShared;
    final cachedFile = outputDir.resolve(cachedName);

    if (!File.fromUri(cachedFile).existsSync()) {
      final url = Uri.parse(
        'https://github.com/$_repo/releases/download/v$version/$remoteName',
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
          stderr.writeln('Downloaded $remoteName (${file.lengthSync()} bytes)');
        } else if (response.statusCode == 404) {
          stderr.writeln(
            'WARNING: $remoteName not found for v$version. '
            'Build the Go library manually or ensure the release has this asset.',
          );
          await response.drain<void>();
          return;
        } else {
          stderr.writeln(
            'WARNING: Failed to download $remoteName: HTTP ${response.statusCode}',
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
