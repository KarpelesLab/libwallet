package wlttx

// Pre-flight guards that run during Transaction.Validate and refuse
// transactions the network would reject anyway — but with a clear,
// structured error instead of an opaque RPC failure several seconds
// later at broadcast time.
//
// v1 covers the Solana-native "send more than you can afford" case
// (insufficient balance, sender below rent-exempt, new recipient not
// funded to rent-exempt). Further checks — contract-is-EOA, drainer
// signals, unlimited approvals — belong to the post-validate simulate
// layer where we have more context.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
)

// PreflightError is returned by pre-flight checks when a transaction is
// guaranteed to fail. It carries a machine-readable Code so apps can
// react (e.g. offer a "Send max" button when code == "below_sender_rent")
// without parsing the human-readable Message.
type PreflightError struct {
	// Code is one of the stable codes documented in the plan
	// (insufficient_balance, below_sender_rent, recipient_rent_not_funded, ...).
	Code string
	// Message is a human-readable description.
	Message string
}

func (e *PreflightError) Error() string { return e.Message }

// IsPreflightError reports whether err is a PreflightError and returns it.
// Apps can use this to surface a structured error to the UI.
func IsPreflightError(err error) (*PreflightError, bool) {
	var pe *PreflightError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}

// preflightSolanaNativeSend verifies that acct has enough balance to
// send tx.Amount lamports on n, accounting for the fixed 5000-lamport
// fee and the rent-exempt minimum the sender must retain. When tx.To
// is provided and the recipient account does not exist yet, the check
// also requires the transfer to at least fund the recipient to its
// rent-exempt minimum.
func preflightSolanaNativeSend(e wltintf.Env, n *wltnet.Network, acct *wltacct.Account, tx *Transaction) error {
	if tx.Amount == nil {
		return nil
	}
	// All Solana amounts are 9-decimal lamports; the amount is
	// fixed-point so .Value() is already lamports.
	amountLamports := tx.Amount.Value()
	if amountLamports == nil || amountLamports.Sign() < 0 {
		return nil
	}

	// Bounded: the pre-flight lookups should never dominate the
	// Validate roundtrip. 5 s is generous.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	balance, err := solanaLamportsBalance(ctx, n, acct.GetAddress())
	if err != nil {
		// Treat RPC failure as non-blocking — the broadcast path
		// will surface any real problem, and we don't want to
		// block a legitimate tx because a node burped.
		return nil
	}

	senderRent, err := SolanaRentExemptMinimum(ctx, n, 0)
	if err != nil {
		senderRent = 890880 // canonical 0-byte system-account rent
	}

	const feeLamports uint64 = 5000

	recipientExists := true
	var recipientRent uint64
	if tx.To != "" {
		exists, rerr := solanaAccountExists(ctx, n, tx.To)
		if rerr == nil && !exists {
			recipientExists = false
			recipientRent = senderRent
		}
	}

	// Cast amount safely; Solana caps at ~18.4e9 SOL total supply
	// so a valid amount fits in uint64 comfortably.
	if !amountLamports.IsUint64() {
		return &PreflightError{
			Code:    "insufficient_balance",
			Message: fmt.Sprintf("amount %s exceeds representable lamports", amountLamports.String()),
		}
	}
	amt := amountLamports.Uint64()

	// Recipient-side rule: if we're funding a brand-new account,
	// the amount alone must meet its rent-exempt minimum.
	if !recipientExists && amt < recipientRent {
		return &PreflightError{
			Code: "recipient_rent_not_funded",
			Message: fmt.Sprintf(
				"recipient account does not exist yet and the transfer amount %d lamports is below the rent-exempt minimum %d lamports required to create it",
				amt, recipientRent),
		}
	}

	// Sender-side rule: balance must cover amount + fee + sender
	// rent reserve. (When recipient needs rent, it comes out of
	// the amount, not an extra reservation on top.)
	required := amt + feeLamports + senderRent
	if required < amt {
		// overflow — impossible for real amounts but guard anyway
		return &PreflightError{
			Code:    "insufficient_balance",
			Message: fmt.Sprintf("required amount overflow (amount=%d, fee=%d, rent=%d)", amt, feeLamports, senderRent),
		}
	}
	if balance < required {
		// Two codes: if the balance would cover amount+fee but
		// not the rent reserve, that's the specific "below rent"
		// case that triggered the whole initiative.
		if balance >= amt+feeLamports {
			return &PreflightError{
				Code: "below_sender_rent",
				Message: fmt.Sprintf(
					"sending %d lamports + fee %d would leave %d lamports on the sender, below the rent-exempt minimum %d. Use Transaction:maxSendable to compute a safe amount.",
					amt, feeLamports, balance-amt-feeLamports, senderRent),
			}
		}
		return &PreflightError{
			Code: "insufficient_balance",
			Message: fmt.Sprintf(
				"balance %d lamports is not enough to send %d + fee %d + rent reserve %d (short by %d lamports)",
				balance, amt, feeLamports, senderRent, required-balance),
		}
	}
	return nil
}
