// Diagnostic prints in setUpAll help track down a CI-side iOS hang.
// ignore_for_file: avoid_print
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:libwallet/libwallet.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  late LibwalletClient client;
  late Directory tempDir;

  setUpAll(() async {
    // Temporary diagnostic timing — test-ios hangs randomly somewhere
    // in setUpAll and the Go-side log.Printf output doesn't reach
    // Flutter's test output on iOS. Each print() here lands in the
    // CI log so the next hang shows which line stalled.
    final t0 = DateTime.now();
    String elapsed() =>
        '${DateTime.now().difference(t0).inMilliseconds}ms';
    print('[setUpAll T+0] getApplicationDocumentsDirectory…');
    final appDir = await getApplicationDocumentsDirectory();
    print('[setUpAll T+${elapsed()}] appDir=${appDir.path}');
    tempDir = Directory('${appDir.path}/libwallet-test');
    if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
    tempDir.createSync();
    print('[setUpAll T+${elapsed()}] tempDir ready');

    // Load the c-shared library via FFI — no platform channel needed.
    // On iOS the lib is statically linked into the app binary.
    // On Android it's a .so in the app's lib directory.
    final DynamicLibrary lib;
    if (Platform.isIOS) {
      lib = DynamicLibrary.process();
    } else if (Platform.isAndroid) {
      lib = DynamicLibrary.open('liblibwallet.so');
    } else {
      throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
    }
    print('[setUpAll T+${elapsed()}] DynamicLibrary loaded');

    print('[setUpAll T+${elapsed()}] LibwalletClient.initialize: enter');
    client = LibwalletClient.initialize(tempDir.path, library: lib);
    print('[setUpAll T+${elapsed()}] LibwalletClient.initialize: exit');

    // Subscribe to the Go-side log stream so init and runtime log
    // lines make it into Flutter's test output too — gives us
    // post-hoc visibility into the Go side even after setUpAll.
    client.logs.listen((e) {
      print('[wltlog ${e.level}] ${e.message}');
    });
    print('[setUpAll T+${elapsed()}] logs subscribed — setUpAll done');
  });

  tearDownAll(() async {
    client.dispose();
    await Future.delayed(const Duration(milliseconds: 200));
    tempDir.deleteSync(recursive: true);
  });

  testWidgets('Info:ping responds', (tester) async {
    final result = await client.info.ping();
    expect(result, isNotNull);
  });

  testWidgets('Info:version returns a string', (tester) async {
    // version() may legitimately return '' on non-tag builds (CI on
    // master, local dev) — the tagged release version is only set
    // by ldflags during a `v*` tag build. Just verify it's a String.
    final version = await client.info.version();
    expect(version, isA<String>());

    // versionInfo() exposes the full struct; gitTag is always set by
    // CI's ldflag plumbing, so it's a more reliable presence check.
    final info = await client.info.versionInfo();
    expect(info.gitTag, isNotEmpty,
        reason: 'gitTag should be set by ldflags on every CI build');
  });

  testWidgets('Info:onboarding returns state', (tester) async {
    final state = await client.info.onboarding();
    expect(state.hasWallet, false);
  });

  testWidgets('Network list returns networks', (tester) async {
    final networks = await client.networks.list();
    expect(networks, isA<List<Network>>());
    expect(networks, isNotEmpty);
  });

  testWidgets('Wallet list is initially empty', (tester) async {
    final wallets = await client.wallets.list();
    expect(wallets, isEmpty);
  });

  testWidgets('create and delete a wallet with password-only keys',
      (tester) async {
    Wallet? createdWallet;
    await for (final event in client.wallets.create(
      name: 'Test Wallet',
      keys: [
        KeyDescription.password('test-pass-1'),
        KeyDescription.password('test-pass-2'),
        KeyDescription.password('test-pass-3'),
      ],
    )) {
      switch (event) {
        case Progress():
          break;
        case Complete(:final value):
          createdWallet = value;
      }
    }

    expect(createdWallet, isNotNull);
    expect(createdWallet!.name, 'Test Wallet');
    expect(createdWallet.keys, hasLength(3));

    // Create an account
    final account = await client.accounts.create(
      name: 'Test Account',
      wallet: createdWallet.id,
      type: 'ethereum',
      index: 0,
    );
    expect(account.address, isNotEmpty);

    // Clean up
    await client.wallets.delete(createdWallet.id);
    final afterDelete = await client.wallets.list();
    expect(afterDelete, isEmpty);
  });
}
