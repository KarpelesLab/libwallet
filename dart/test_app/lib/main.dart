import 'package:flutter/material.dart';

/// Minimal app shell -- exists only so Flutter integration tests can run.
/// The actual test logic lives in integration_test/.
void main() {
  runApp(const MaterialApp(
    home: Scaffold(
      body: Center(child: Text('libwallet test host')),
    ),
  ));
}
