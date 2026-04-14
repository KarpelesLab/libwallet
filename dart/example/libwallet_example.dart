// Minimal libwallet usage example.
//
// Shows how to initialize the client, create a wallet with progress updates,
// derive an account, query balance, listen for Web3 request events, and
// shut down cleanly.
//
// Run with:  dart run example/libwallet_example.dart <data-dir>
//
// See `doc/webview_integration.md` in the package for the full dApp-
// connection walkthrough (EIP-6963 / Solana Wallet Standard / mpurse).

import 'dart:io';

import 'package:libwallet/libwallet.dart';

Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    stderr.writeln('usage: dart run libwallet_example.dart <data-dir>');
    exit(64);
  }
  final dataDir = args.first;

  final client = LibwalletClient.initialize(dataDir);

  // 1. Confirm the native library is live.
  final pong = await client.info.ping();
  print('ping: $pong');
  print('version: ${await client.info.version()}');

  // 2. Listen for dApp requests in the background. In a real app this
  // would drive the approval sheet; here we just log and reject.
  final pendingSub = client.pendingRequests.listen((req) async {
    print('pending request: type=${req.type} host=${req.host}');
    await client.requests.reject(req.id);
  });

  // 3. Create a wallet (or reuse an existing one). Password-only keys
  // are shown for brevity — real apps mix StoreKey, RemoteKey, Password.
  final existing = await client.wallets.list();
  late final Wallet wallet;
  if (existing.isEmpty) {
    print('creating wallet…');
    Wallet? created;
    await for (final event in client.wallets.create(
      name: 'Example Wallet',
      keys: [
        KeyDescription.password('pass-1'),
        KeyDescription.password('pass-2'),
        KeyDescription.password('pass-3'),
      ],
    )) {
      switch (event) {
        case Progress(:final fraction):
          stdout.write('\r  ${(fraction * 100).toStringAsFixed(1)}%   ');
        case Complete(:final value):
          stdout.writeln();
          created = value;
      }
    }
    wallet = created!;
    print('created wallet ${wallet.id}');
  } else {
    wallet = existing.first;
    print('using existing wallet ${wallet.id}');
  }

  // 4. Make sure we have an Ethereum account.
  final accounts = await client.accounts.list(wallet: wallet.id);
  final account = accounts.isNotEmpty
      ? accounts.first
      : await client.accounts.create(
          name: 'Main',
          wallet: wallet.id,
          type: 'ethereum',
          index: 0,
        );
  print('account ${account.id} -> ${account.address}');

  // 5. Query native balance on the current network.
  final assets = await client.assets.list();
  for (final a in assets) {
    print('${a.symbol}: ${a.amount}');
  }

  // 6. Clean up — cancel subscriptions and dispose the transport.
  await pendingSub.cancel();
  client.dispose();
}
