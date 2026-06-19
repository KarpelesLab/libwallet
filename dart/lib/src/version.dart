// Hardcoded Dart package version. Must be kept in lockstep with
// `version:` in pubspec.yaml — there is no Dart-side equivalent of
// pub.dev's version constant accessible at runtime without a Flutter-
// or dart:io-only API, so a const is the most portable answer.
//
// Verified by `dart/test/version_constant_test.dart`: the test parses
// pubspec.yaml and fails the build if the two drift.
//
// The constant is used by `LibwalletClient.initialize` to call
// `Info:version` and detect a stale-binary mismatch — the post-upgrade
// failure mode where the Dart side has been bumped but the linked
// native library is still from the previous release.

const String libwalletPackageVersion = '0.4.65';
