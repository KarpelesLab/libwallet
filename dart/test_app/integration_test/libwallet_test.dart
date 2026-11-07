// Diagnostic prints in setUpAll help track down a CI-side iOS hang.
// ignore_for_file: avoid_print
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:libwallet/libwallet.dart';

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
    // Use `dart:io`'s sandboxed temp dir instead of path_provider's
    // `getApplicationDocumentsDirectory()`. On iOS+Android the latter
    // pulls in `path_provider_foundation` → `objective_c`, which
    // ships an arm64e-only simulator framework that the Apple Silicon
    // GitHub runner refuses to load (the framework's fat binary has
    // arm64e but the sim process is plain arm64). systemTemp resolves
    // to `NSTemporaryDirectory()` on iOS — writable inside the
    // sandbox, no plugin needed.
    print('[setUpAll T+0] Directory.systemTemp.createTempSync…');
    tempDir = Directory.systemTemp.createTempSync('libwallet-test-');
    print('[setUpAll T+${elapsed()}] tempDir=${tempDir.path}');

    // Load the c-shared library via FFI — no platform channel needed.
    // On iOS the lib is statically linked into the app binary.
    // On Android it's the .so the build hook bundles, under the same
    // versioned name the Kotlin vault bridge loads: opening another copy
    // would leave the vault without its JNI hookup.
    final DynamicLibrary lib;
    if (Platform.isIOS) {
      lib = DynamicLibrary.process();
    } else if (Platform.isAndroid) {
      final abi = Abi.current() == Abi.androidArm64 ? 'arm64' : 'x64';
      lib = DynamicLibrary.open(
          'liblibwallet-android-$abi-v$libwalletPackageVersion.so');
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

  // Use plain `test()` rather than `testWidgets()` — none of these
  // tests render any widgets, they just exercise the FFI bridge.
  // testWidgets installs an end-of-test SemanticsHandle verifier that
  // intermittently fails on iOS under xcodebuild test because XCTest
  // enables system accessibility for XCUIElement introspection, which
  // makes Flutter's renderer ensure semantics asynchronously during
  // the test body. The handle count goes up between the verifier's
  // start-of-test snapshot and end-of-test check, and the first
  // testWidgets case fails with "A SemanticsHandle was active at the
  // end of the test". integration_test collects results from both
  // test() and testWidgets() so picking the right primitive sidesteps
  // the issue entirely.

  test('Info:ping responds', () async {
    final result = await client.info.ping();
    expect(result, isNotNull);
  });

  test('Info:version returns a string', () async {
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

  test('Info:onboarding returns state', () async {
    final state = await client.info.onboarding();
    expect(state.hasWallet, false);
  });

  test('Network list returns networks', () async {
    final networks = await client.networks.list();
    expect(networks, isA<List<Network>>());
    expect(networks, isNotEmpty);
  });

  test('Wallet list is initially empty', () async {
    final wallets = await client.wallets.list();
    expect(wallets, isEmpty);
  });

  test('create and delete a wallet with password-only keys', () async {
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

  // The secure vault backend needs a real platform keychain/keystore, so it
  // is only exercisable here (host tests use the password backend).
  test('Vault: a secure entry protects an MPC share on the device', () async {
    final caps = await client.vault.capabilities();
    print('[vault] capabilities: secure=${caps.secure} hardware=${caps.hardware} '
        'biometry=${caps.biometry} provider=${caps.provider} reason=${caps.reason}');
    if (!caps.secure) {
      // CI builds pass --dart-define=LIBWALLET_REQUIRE_SECURE_VAULT=true so a
      // regression (e.g. losing the keychain entitlement) fails, not skips.
      const require = bool.fromEnvironment('LIBWALLET_REQUIRE_SECURE_VAULT');
      expect(require, isFalse, reason: 'secure vault required: ${caps.reason}');
      print('[vault] SKIP: no secure storage in this build (${caps.reason})');
      return;
    }
    // No user-presence requirement: an automated run cannot answer a prompt.
    final entry = await client.vault.create(
        kind: 'storekey', policy: const VaultPolicy(userPresence: false));
    expect(entry.backend, 'secure');
    expect(entry.provider, caps.provider);
    expect(entry.publicKey, isNotEmpty);

    Wallet? w;
    await for (final e in client.wallets.create(name: 'Vault wallet', keys: [
      KeyDescription.vault(entry.id),
      KeyDescription.password('vault-pass-2'),
      KeyDescription.password('vault-pass-3'),
    ])) {
      if (e case Complete(:final value)) w = value;
    }
    final wallet = w!;
    expect(wallet.keys[0].key, entry.publicKey);
    final acct = await client.accounts
        .create(name: 'V', wallet: wallet.id, type: 'ethereum', index: 0);
    Future<SignedMessage> sign() => client.accounts.signMessage(acct.id,
        message: Uint8List.fromList('vault'.codeUnits),
        keys: [
          KeyDescription.vault(entry.id, walletKeyId: wallet.keys[0].id).toJson(),
          KeyDescription.password('vault-pass-2').withId(wallet.keys[1].id).toJson(),
        ]);
    final sig = await sign();
    expect(sig.signature, startsWith('0x'));

    // Deleting the entry destroys the device key: the share is gone with it.
    expect(await client.vault.delete(entry.id), isTrue);
    await expectLater(sign(), throwsA(anything));
    await client.wallets.delete(wallet.id);
  });

  // Opt-in (--dart-define=LIBWALLET_VAULT_PROMPT_TEST=true): a user-presence
  // entry, so unsealing shows the OS prompt. Needs a screen lock and someone
  // (or an adb script typing the PIN) to answer it.
  test('Vault: a user-presence entry unseals only after the OS prompt', () async {
    // "true": answer the prompt; "cancel": lock the vault while it is up.
    const mode = String.fromEnvironment('LIBWALLET_VAULT_PROMPT_TEST');
    if (mode.isEmpty) return;
    final entry = await client.vault.create(
        kind: 'data', policy: const VaultPolicy(exportable: true));
    print('[vault] prompt test ($mode): created ${entry.id}, unsealing');
    final unseal = client.vault.export(entry.id, reason: 'libwallet vault test');
    if (mode == 'cancel') {
      // Locking the vault dismisses a pending prompt (as backgrounding does).
      await Future<void>.delayed(const Duration(seconds: 4));
      await client.vault.lock();
      await expectLater(unseal,
          throwsA(predicate((e) => e.toString().contains('user cancelled'))));
      print('[vault] prompt test: cancel reported as "user cancelled"');
    } else {
      expect(await unseal, isNotEmpty);
      print('[vault] prompt test: unsealed after the prompt');
    }
    await client.vault.delete(entry.id);
  }, timeout: const Timeout(Duration(minutes: 2)));
}
