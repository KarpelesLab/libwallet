// Bump (or verify) the libwallet Dart package version.
//
// Single source of truth for the package version is `pubspec.yaml`'s
// `version:` line. `lib/src/version.dart` carries the same string as
// `libwalletPackageVersion` so the runtime mismatch check has a value
// to compare against. This script keeps the two in sync.
//
// Usage:
//   dart run tools/bump_version.dart 0.4.0   # set explicit version
//   dart run tools/bump_version.dart --patch # 0.3.29 → 0.3.30
//   dart run tools/bump_version.dart --minor # 0.3.29 → 0.4.0
//   dart run tools/bump_version.dart --major # 0.3.29 → 1.0.0
//   dart run tools/bump_version.dart --check # exit 1 if any tracked
//                                            #   file disagrees with
//                                            #   pubspec.yaml
//
// CI calls --check on every push (see .github/workflows/dart-test.yml).
// Releases call this directly: bump → commit → tag → push.

import 'dart:io';

const _pubspecPath = 'pubspec.yaml';
const _versionDartPath = 'lib/src/version.dart';

void main(List<String> args) {
  if (args.length != 1) {
    _usage();
    exit(64);
  }

  final mode = args[0];
  final current = _readPubspecVersion();

  switch (mode) {
    case '--check':
      final inDart = _readVersionDart();
      if (inDart != current) {
        stderr.writeln(
          'version drift detected:\n'
          '  $_pubspecPath        → $current\n'
          '  $_versionDartPath → $inDart\n'
          '\n'
          'Fix with: (cd ${Directory.current.path} && '
          'dart run tools/bump_version.dart $current)',
        );
        exit(1);
      }
      stdout.writeln('✓ version $current consistent');
      return;

    case '--patch':
      _setVersion(current, _bump(current, 2));
      return;
    case '--minor':
      _setVersion(current, _bump(current, 1));
      return;
    case '--major':
      _setVersion(current, _bump(current, 0));
      return;

    default:
      if (!RegExp(r'^\d+\.\d+\.\d+$').hasMatch(mode)) {
        stderr.writeln('not a valid semver triple (X.Y.Z): $mode');
        exit(64);
      }
      _setVersion(current, mode);
  }
}

String _readPubspecVersion() {
  final file = File(_pubspecPath);
  if (!file.existsSync()) {
    stderr.writeln(
      'cannot find $_pubspecPath — run from the dart/ directory '
      '(currently in ${Directory.current.path})',
    );
    exit(2);
  }
  final match = RegExp(r'^version:\s*(\S+)\s*$', multiLine: true)
      .firstMatch(file.readAsStringSync());
  if (match == null) {
    stderr.writeln('no `version:` line in $_pubspecPath');
    exit(2);
  }
  return match.group(1)!;
}

String _readVersionDart() {
  final file = File(_versionDartPath);
  if (!file.existsSync()) {
    stderr.writeln('cannot find $_versionDartPath');
    exit(2);
  }
  final match =
      RegExp(r"libwalletPackageVersion\s*=\s*'([^']+)'")
          .firstMatch(file.readAsStringSync());
  if (match == null) {
    stderr.writeln('no libwalletPackageVersion in $_versionDartPath');
    exit(2);
  }
  return match.group(1)!;
}

void _setVersion(String from, String to) {
  // pubspec.yaml
  final pubspec = File(_pubspecPath);
  pubspec.writeAsStringSync(pubspec.readAsStringSync().replaceFirst(
        RegExp(r'^version:\s*\S+\s*$', multiLine: true),
        'version: $to',
      ));

  // lib/src/version.dart
  final dart = File(_versionDartPath);
  dart.writeAsStringSync(dart.readAsStringSync().replaceFirst(
        RegExp(r"libwalletPackageVersion\s*=\s*'[^']+'"),
        "libwalletPackageVersion = '$to'",
      ));

  stdout.writeln('bumped $from → $to');
  stdout.writeln('  $_pubspecPath');
  stdout.writeln('  $_versionDartPath');
  stdout.writeln(
    '\nNext steps:\n'
    '  1. add a CHANGELOG.md entry for $to\n'
    '  2. dart analyze && dart test\n'
    '  3. git add -p && git commit -m "bump Dart package to $to"\n'
    '  4. git tag v$to && git push origin master v$to',
  );
}

String _bump(String version, int component) {
  final parts = version.split('.').map(int.parse).toList();
  if (parts.length != 3) {
    stderr.writeln('non-semver version in pubspec: $version');
    exit(2);
  }
  parts[component]++;
  for (var i = component + 1; i < 3; i++) {
    parts[i] = 0;
  }
  return parts.join('.');
}

void _usage() {
  stderr.writeln(
    'Usage:\n'
    '  dart run tools/bump_version.dart <X.Y.Z>     set explicit version\n'
    '  dart run tools/bump_version.dart --patch     X.Y.(Z+1)\n'
    '  dart run tools/bump_version.dart --minor     X.(Y+1).0\n'
    '  dart run tools/bump_version.dart --major     (X+1).0.0\n'
    '  dart run tools/bump_version.dart --check     verify lockstep, exit 1 on drift',
  );
}
