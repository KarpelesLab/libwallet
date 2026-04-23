package wltacct

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/KarpelesLab/secp256k1"
)

// SignEthereumDigest signs a 32-byte Ethereum keccak digest and returns
// the 65-byte Ethereum-wire signature: R(32) || S(32) || V(1) where V
// is 27 or 28 (legacy v, NOT EIP-155 chain-id-adjusted).
//
// Ethereum off-chain signing flows — personal_sign, eth_signTypedData
// (v3 / v4), Sign-In With Ethereum (SIWE), Snapshot, Permit2, OpenSea
// listings, etc. — all expect this exact shape. ecrecover and every
// JS-side verifier (viem.verifyTypedData, ethers.verifyMessage, …)
// will reject anything else with "Invalid signature v value" or a
// silent address mismatch.
//
// The TSS signer returns DER-encoded ECDSA bytes and drops the
// recovery byte; we recover it deterministically by trying both
// possible v values and picking the one that recovers the account's
// known pubkey. Same approach as Bitcoin's SignCompact, just with
// a different output layout (Bitcoin puts the header byte first;
// Ethereum puts v last).
//
// EIP-155 chain-id adjustment is intentionally NOT applied here —
// that lives in the on-chain transaction signing path. Off-chain
// flows always use the legacy v ∈ {27, 28}.
func (a *Account) SignEthereumDigest(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if a.Curve != "secp256k1" {
		return nil, errors.New("SignEthereumDigest requires a secp256k1 account")
	}
	derSig, err := a.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("tss sign: %w", err)
	}
	sig, err := secp256k1.ParseDERSignature(derSig)
	if err != nil {
		return nil, fmt.Errorf("parse tss signature: %w", err)
	}
	pub := a.PublicKey()
	if pub == nil {
		return nil, errors.New("account has no usable public key")
	}
	if !sig.BruteforceRecoveryCode(digest, pub) {
		return nil, errors.New("could not determine signature recovery code")
	}
	// recoveryCodeFirst=false  → R(32) || S(32) || (recovery + 27)
	return sig.ExportCompact(false, 27), nil
}
