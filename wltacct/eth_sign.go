package wltacct

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/secp256k1"
	"golang.org/x/crypto/sha3"
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

// EthPersonalEcRecover implements `personal_ecRecover` (and is the
// inverse of personal_sign): given the original message and the
// 65-byte Ethereum-wire signature R(32) || S(32) || V(1), it
// reconstructs the EIP-191 hashing prefix, runs ECDSA recovery and
// returns the 0x-prefixed EIP-55 address that signed it.
//
// V is accepted as either {27, 28} (legacy) or {0, 1} (raw recovery
// code) — same tolerance MetaMask, ethers.js and viem apply, since
// historical signers have produced both.
//
// This runs entirely locally; there is no JSON-RPC endpoint to relay
// to (most public Ethereum nodes return -32601 because it's a wallet-
// side operation, not a chain operation).
func EthPersonalEcRecover(msg, sig []byte) (string, error) {
	if len(sig) != 65 {
		return "", fmt.Errorf("personal_ecRecover: signature must be 65 bytes, got %d", len(sig))
	}
	v := sig[64]
	switch {
	case v == 27 || v == 28:
		v -= 27
	case v == 0 || v == 1:
		// raw recovery code, leave as-is
	default:
		return "", fmt.Errorf("personal_ecRecover: invalid v byte %d (want 0/1/27/28)", v)
	}

	prefix := append([]byte("\x19Ethereum Signed Message:\n"), []byte(strconv.Itoa(len(msg)))...)
	digest := cryptutil.Hash(append(prefix, msg...), sha3.NewLegacyKeccak256)

	// secp256k1.ParseCompactSignature expects (header || R || S) — the
	// Bitcoin layout. We have (R || S || V), so reshuffle.
	btc := make([]byte, 65)
	btc[0] = v + 27
	copy(btc[1:], sig[:64])
	parsed, _, err := secp256k1.ParseCompactSignature(btc)
	if err != nil {
		return "", fmt.Errorf("personal_ecRecover: parse signature: %w", err)
	}
	pub, err := parsed.RecoverPublicKey(digest)
	if err != nil {
		return "", fmt.Errorf("personal_ecRecover: recover pubkey: %w", err)
	}
	out, err := outscript.New(pub).Out("eth")
	if err != nil {
		return "", fmt.Errorf("personal_ecRecover: derive address: %w", err)
	}
	addr, err := out.Address()
	if err != nil {
		return "", fmt.Errorf("personal_ecRecover: format address: %w", err)
	}
	return addr, nil
}
