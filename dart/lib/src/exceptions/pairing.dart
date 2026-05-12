/// Typed exceptions for the ClawdWallet pairing flow
/// (`LibwalletClient.clawdWallet.pair`).
///
/// Catch [PairingException] for "any pair() failure"; switch on the
/// concrete subtype when the UI needs to branch (e.g. a different message
/// for `token_consumed` vs `token_expired`, or a security-flavoured banner
/// for [PairingIdentityMismatchException]).
///
/// Wire codes from the contract
/// (`tibaneapp/docs/clawdwallet-pairing.md`) map 1:1 to subclasses below.
/// Three additional subclasses cover failures that happen before or around
/// the agent's reply: [PairingURLMalformedException] (caught locally before
/// any Spot traffic), [PairingAgentUnreachableException] (no answer from
/// the agent), and [PairingIdentityMismatchException] (response's
/// `agent_spot_id` did not match the URL — treat as a redirection attack).
library;

/// Common base for every pair() failure.
abstract class PairingException implements Exception {
  /// Human-readable detail. Already short enough to surface verbatim in a
  /// snackbar; not localised — apps that need translations should branch
  /// on the runtime type, not the message.
  final String message;
  const PairingException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// The pairing URL didn't parse, used the wrong scheme, or was missing
/// `agent` / `token`. No Spot traffic happens — this is caught locally.
class PairingURLMalformedException extends PairingException {
  const PairingURLMalformedException(
      [super.message = 'Pairing URL is malformed']);
}

/// The agent could not be contacted within the timeout — typically Spot
/// transport failure or the agent host being offline. Retry by asking the
/// user to scan a fresh URL (the token survives unless the agent actually
/// processed and consumed it; if in doubt, generate a new one).
class PairingAgentUnreachableException extends PairingException {
  const PairingAgentUnreachableException(
      [super.message =
          'Could not reach the agent over Spot within the timeout']);
}

/// The agent did not recognise the token — typo, wrong agent, or the
/// agent process was restarted (tokens are in-memory only).
class PairingTokenInvalidException extends PairingException {
  const PairingTokenInvalidException(
      [super.message = 'Pairing token is not recognised by this agent']);
}

/// The token's 5-minute TTL elapsed between agent generation and the
/// mobile attempting to pair. Re-run `clawdwallet pair` for a fresh URL.
class PairingTokenExpiredException extends PairingException {
  const PairingTokenExpiredException(
      [super.message = 'Pairing token has expired (5 min TTL)']);
}

/// The token has already been used for a successful pair. Tokens are
/// single-use; re-run `clawdwallet pair` for a fresh URL.
class PairingTokenConsumedException extends PairingException {
  const PairingTokenConsumedException(
      [super.message = 'Pairing token has already been used']);
}

/// The agent rejected the request as malformed. Indicates a contract
/// mismatch — usually a libwallet / agent version drift. Updating either
/// side normally resolves it.
class PairingBadRequestException extends PairingException {
  const PairingBadRequestException(
      [super.message = 'Agent rejected the pair request as malformed']);
}

/// The `agent_spot_id` in the response did not equal the `agent` parameter
/// in the URL the user opened. Treat as a redirection attack and surface a
/// loud, security-flavoured error — DO NOT proceed to keygen with the
/// returned identity.
///
/// The two ids are exposed so the host can log them for incident
/// triage; do not display either to the user.
class PairingIdentityMismatchException extends PairingException {
  /// Agent id from the URL the user opened.
  final String urlAgentSpotId;

  /// Agent id the responder claimed in its reply.
  final String responseAgentSpotId;

  const PairingIdentityMismatchException({
    required this.urlAgentSpotId,
    required this.responseAgentSpotId,
    String message =
        'Pairing response identity does not match the URL — possible redirection attack',
  }) : super(message);
}
