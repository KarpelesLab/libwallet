// XCTest entry point for the libwallet Dart integration tests on iOS.
//
// Replaces `flutter test integration_test/...` (which attaches to the
// in-sim Dart VM Service over Bonjour + mDNS — the discovery race
// that produced the "awaiting connection to test device" hangs in
// CI). The INTEGRATION_TEST_IOS_RUNNER macro generates an
// XCTestCase whose +testInvocations triggers FLTIntegrationTestRunner,
// which runs the dart tests in-process through Flutter's own engine
// and reports results through the XCTest runtime. No mDNS, no DDS,
// no Bonjour — XCTest's native IPC.
//
// The dart entry point picked up at test time is whatever the most
// recent `flutter build ios --config-only <target>` wrote into
// Generated.xcconfig (FLUTTER_TARGET). CI sets it to
// integration_test/libwallet_test.dart before invoking
// `xcodebuild test`.

#import <XCTest/XCTest.h>
#import "FLTIntegrationTestRunner.h"
#import "IntegrationTestIosTest.h"

INTEGRATION_TEST_IOS_RUNNER(RunnerTests)
