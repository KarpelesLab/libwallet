import '../client/response.dart';
import '../client/transport.dart';
import '../exceptions/pairing.dart';
import '../models/agent_identity.dart';

/// ClawdWallet pairing API.
///
/// Stage 1 surface is a single call: hand a `clawd://pair?...` URL in,
/// get a verified [AgentIdentity] back, or one of the typed
/// [PairingException] subclasses on failure. The host app does not speak
/// Spot — libwallet drives the entire handshake.
///
/// See the wire contract in
/// `tibaneapp/docs/clawdwallet-pairing.md` and the typed-exception
/// catalogue in `pairing.dart`.
class ClawdWalletApi {
  final Transport _conn;
  ClawdWalletApi(this._conn);

  /// Verify a `clawd://pair?agent=...&token=...` URL by handshaking with
  /// the agent over Spot, and return the agent's verified identity.
  ///
  /// Throws a typed [PairingException] subclass on failure — see that file
  /// for the catalogue. Catch [PairingException] for a single "pair failed"
  /// branch in the UI, or switch on the runtime type for per-error
  /// messaging.
  ///
  /// Idempotent in name only: pairing tokens are single-use, so a second
  /// call with the same URL throws [PairingTokenConsumedException]. Each
  /// retry needs a fresh URL from `clawdwallet pair`.
  Future<AgentIdentity> pair(String url) async {
    try {
      final data = await _conn
          .request('ClawdWallet:pair', 'POST', {'url': url});
      return AgentIdentity.fromJson(Map<String, dynamic>.from(data as Map));
    } on LibwalletException catch (e) {
      throw _toPairingException(e);
    }
  }

  /// Map a libwallet error string to a typed pairing exception. Codes are
  /// the verbatim Error() strings from the Go-side sentinels in
  /// `wltwallet/pair.go`. Unknown codes fail closed as
  /// [PairingBadRequestException] — surfacing them as a generic
  /// [LibwalletException] would defeat the typed-exception contract.
  PairingException _toPairingException(LibwalletException e) {
    // The Go side stuffs the wire code into the error message via
    // `errors.New("<code>")`; the FFI wrapper carries it through into
    // LibwalletException.message verbatim. For wrapped errors
    // (`fmt.Errorf("wrap: %w", sentinel)`) we still need to recognise
    // the embedded code, so allow a simple prefix/suffix containment
    // check after the exact match.
    final msg = e.message;

    bool has(String code) => msg == code || msg.contains(code);

    if (has('url_malformed')) {
      return PairingURLMalformedException(msg);
    }
    if (has('agent_unreachable')) {
      return PairingAgentUnreachableException(msg);
    }
    if (has('token_invalid')) {
      return PairingTokenInvalidException(msg);
    }
    if (has('token_expired')) {
      return PairingTokenExpiredException(msg);
    }
    if (has('token_consumed')) {
      return PairingTokenConsumedException(msg);
    }
    if (has('identity_mismatch')) {
      // We don't have the URL/response ids on this side — the Go layer
      // collapsed the mismatch into a single sentinel. The host can log
      // the URL it passed in; the response id stays opaque.
      return PairingIdentityMismatchException(
        urlAgentSpotId: '',
        responseAgentSpotId: '',
        message: msg,
      );
    }
    // Anything else is treated as bad_request — fail closed.
    return PairingBadRequestException(msg);
  }
}
