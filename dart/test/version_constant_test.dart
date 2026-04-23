import 'dart:io';

import 'package:libwallet/libwallet.dart' show libwalletPackageVersion;
import 'package:test/test.dart';

// Guards against the "I bumped pubspec.yaml but forgot to bump
// lib/src/version.dart" footgun. The constant has to be a plain
// `const String` so it inlines into release builds — there is no
// portable runtime API to read pubspec.yaml from a published Dart
// package, so we hand-mirror the value and verify here.

void main() {
  test('libwalletPackageVersion matches pubspec.yaml version', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    final match = RegExp(r'^version:\s*(\S+)\s*$', multiLine: true)
        .firstMatch(pubspec);
    expect(match, isNotNull,
        reason: 'pubspec.yaml is missing a `version:` line');
    final pubspecVersion = match!.group(1);
    expect(libwalletPackageVersion, equals(pubspecVersion),
        reason:
            'lib/src/version.dart::libwalletPackageVersion drifted from '
            'pubspec.yaml — they have to move in lockstep so the runtime '
            'mismatch check (LibwalletClient._verifyVersionMatch) compares '
            'against the right value.\n'
            '\n'
            'Run: dart run tools/bump_version.dart $pubspecVersion');
  });
}
