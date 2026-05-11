package wltacct

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/pobj"
	"golang.org/x/crypto/sha3"
)

// Direct signing endpoints for wallet hosts (the application embedding
// libwallet). These bypass the Web3 request/approval flow which exists
// for sandboxed dApps. The host knows what it's signing and provides
// keys directly.
//
// All endpoints accept binary data as base64 (browser-safe) and return
// signatures in their canonical chain encoding (base58 for Solana,
// hex 0x-prefixed for EVM).

func init() {
	pobj.RegisterStatic("Account:signMessage", accountSignMessage)
	pobj.RegisterStatic("Account:signTransaction", accountSignTransaction)
	pobj.RegisterStatic("Account:signAndSendTransaction", accountSignAndSendTransaction)
}

// accountSignMessage signs an arbitrary message with the account's key.
//
// Mode selection:
//   - "solana"          → raw EdDSA over the message bytes; returns base58 sig.
//   - "evm" / "personal_sign" → EVM `personal_sign`: keccak256 of the
//     "\x19Ethereum Signed Message:\n<len>" prefix + message; returns 0x-hex sig.
//   - "raw"             → signs the message bytes as-is (caller already hashed);
//     returns base64 sig. For advanced use.
//
// Defaults to "solana" for ed25519 accounts, "evm" for secp256k1 accounts.
func accountSignMessage(ctx *apirouter.Context, in struct {
	Message string                       `json:"Message"` // base64 of bytes to sign
	Keys    []*wltsign.KeyDescription    `json:"Keys"`
	Mode    string                       `json:"Mode"`
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	acct := apirouter.GetObject[Account](ctx, "Account")
	if acct == nil {
		return nil, errors.New("account required")
	}
	if len(in.Keys) == 0 {
		return nil, errors.New("Keys are required")
	}
	if in.Message == "" {
		return nil, errors.New("Message is required")
	}

	msgBytes, err := base64.StdEncoding.DecodeString(in.Message)
	if err != nil {
		return nil, fmt.Errorf("Message must be base64-encoded: %w", err)
	}

	mode := in.Mode
	if mode == "" {
		if acct.Curve == "ed25519" {
			mode = "solana"
		} else {
			mode = "evm"
		}
	}

	signOpt := &wltsign.Opts{
		Context: ctx,
		IL:      acct.IL,
		Keys:    in.Keys,
	}

	switch mode {
	case "solana":
		// Self-heal the Ed25519 pubkey if we're still on the legacy
		// encoding. Done before signing so "publicKey" in the
		// response is the corrected address.
		_, _ = EnsureEd25519PubkeyOnAccount(ctx, acct, in.Keys)
		sig, err := acct.Sign(nil, msgBytes, signOpt)
		if err != nil {
			return nil, fmt.Errorf("solana sign failed: %w", err)
		}
		return map[string]any{
			"signature": base58.Bitcoin.Encode(sig),
			"publicKey": acct.Address,
		}, nil
	case "evm", "personal_sign":
		// EIP-191 personal_sign — wire format is R || S || V, V ∈ {27, 28}.
		// SignEthereumDigest returns the 65-byte form ecrecover expects;
		// `acct.Sign(...)` alone returns DER, which every off-chain
		// verifier rejects.
		prefix := []byte("\x19Ethereum Signed Message:\n" + strconv.Itoa(len(msgBytes)))
		full := append(prefix, msgBytes...)
		digest := cryptutil.Hash(full, sha3.NewLegacyKeccak256)
		sig, err := acct.SignEthereumDigest(digest, signOpt)
		if err != nil {
			return nil, fmt.Errorf("evm sign failed: %w", err)
		}
		return map[string]any{
			"signature": "0x" + hex.EncodeToString(sig),
		}, nil
	case "raw":
		// Caller has already hashed; sign the bytes directly.
		var rng = rand.Reader
		if acct.Curve == "ed25519" {
			rng = nil
		}
		sig, err := acct.Sign(rng, msgBytes, signOpt)
		if err != nil {
			return nil, fmt.Errorf("raw sign failed: %w", err)
		}
		return map[string]any{
			"signature": base64.StdEncoding.EncodeToString(sig),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported sign mode: %s", mode)
	}
}

// accountSignTransaction signs an unsigned (or partially-signed) transaction
// with the account's key. The transaction format depends on the chain:
//
//   - Solana: base64 of a serialized Solana tx with placeholder signatures.
//     The first 64-byte signature slot is replaced with the real signature.
//
// EVM transaction signing is intentionally not exposed here — use
// `Transaction:signAndSend` with structured params instead, which handles
// gas estimation, nonce, fee format, and broadcast in one step.
func accountSignTransaction(ctx *apirouter.Context, in struct {
	Transaction string                    `json:"Transaction"` // base64
	Keys        []*wltsign.KeyDescription `json:"Keys"`
}) (any, error) {
	signed, _, err := signSolanaTransaction(ctx, in.Transaction, in.Keys)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"transaction": base64.StdEncoding.EncodeToString(signed),
	}, nil
}

// accountSignAndSendTransaction signs a transaction and broadcasts it via the
// network's RPC. Returns the broadcast txid/signature.
func accountSignAndSendTransaction(ctx *apirouter.Context, in struct {
	Transaction string                    `json:"Transaction"` // base64
	Keys        []*wltsign.KeyDescription `json:"Keys"`
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	signed, acct, err := signSolanaTransaction(ctx, in.Transaction, in.Keys)
	if err != nil {
		return nil, err
	}
	_ = acct // currently only Solana supported

	// Pick a Solana RPC. Using CurrentNetwork would send the tx to whatever
	// the user is browsing in the wallet UI (often an EVM RPC), which then
	// returns "The method sendTransaction does not exist".
	net, err := wltnet.SolanaBroadcastNetwork(e)
	if err != nil {
		return nil, fmt.Errorf("failed to get Solana network: %w", err)
	}
	txBase58 := base58.Bitcoin.Encode(signed)
	result, err := net.DoRPC("sendTransaction", txBase58, map[string]any{"encoding": "base58"})
	if err != nil {
		return nil, fmt.Errorf("sendTransaction failed: %w", err)
	}
	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return nil, fmt.Errorf("failed to parse send response: %w", err)
	}
	wltintf.NotifyTxBroadcast(e)
	return map[string]any{
		"signature": txHash,
	}, nil
}

// signSolanaTransaction extracts the Solana message portion, signs it with
// the account's TSS, and returns the transaction with the first signature
// slot replaced.
func signSolanaTransaction(ctx *apirouter.Context, txB64 string, keys []*wltsign.KeyDescription) ([]byte, *Account, error) {
	acct := apirouter.GetObject[Account](ctx, "Account")
	if acct == nil {
		return nil, nil, errors.New("account required")
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("Keys are required")
	}
	if txB64 == "" {
		return nil, nil, errors.New("Transaction is required")
	}
	if acct.Curve != "ed25519" {
		return nil, nil, errors.New("signTransaction currently supports Solana (ed25519) only — use Transaction:signAndSend for EVM/Bitcoin")
	}

	// Pre-flight Ed25519 pubkey self-heal: if the wallet was created
	// under the legacy X-coord encoding, repair it now and persist
	// the corrected Account so the dApp's NEXT read of
	// window.solana.publicKey returns the right address.
	// The CURRENT tx was built with the old address, so signing it
	// will still be rejected by Solana — that's OK, the user's app
	// will retry after the pubkey refreshes on the JS side.
	_, _ = EnsureEd25519PubkeyOnAccount(ctx, acct, keys)

	txBytes, err := base64.StdEncoding.DecodeString(txB64)
	if err != nil {
		return nil, nil, fmt.Errorf("Transaction must be base64-encoded: %w", err)
	}

	msg, err := solanaExtractMessage(txBytes)
	if err != nil {
		return nil, nil, err
	}

	signOpt := &wltsign.Opts{
		Context: ctx,
		IL:      acct.IL,
		Keys:    keys,
	}
	sig, err := acct.Sign(nil, msg, signOpt)
	if err != nil {
		return nil, nil, fmt.Errorf("solana sign failed: %w", err)
	}

	// Decode the wallet's pubkey so we can find which signature slot it
	// belongs in. Sponsored transactions put the relay (feePayer) at slot
	// 0 and the wallet owner at slot 1+, so writing unconditionally to
	// slot 0 silently corrupted the relay's slot.
	pubkey, err := base58.Bitcoin.Decode(acct.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode account address %q: %w", acct.Address, err)
	}
	signed, err := solanaInsertSignature(txBytes, sig, pubkey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to insert signature: %w", err)
	}
	return signed, acct, nil
}
