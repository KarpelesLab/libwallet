package wltbase

// Unified approval handlers for the transaction_sign and
// message_sign request types. Method-dispatched against the rich
// Value payload built at emit time — same per-chain signing logic
// as the previous per-method approve cases, just routed from a
// single entry point.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/libwallet/wlttx"
	"golang.org/x/crypto/sha3"
)

// approveTransactionSign drives the chain-specific signer for any
// "transaction_sign" approval. Routes by Method on the
// TransactionSignValue payload built at emit time.
func approveTransactionSign(ctx context.Context, e *env, req *request, keys []*wltsign.KeyDescription) error {
	if len(keys) == 0 {
		return errors.New("transaction_sign approval requires Keys")
	}
	v, err := decodeTxSignValue(req.Value)
	if err != nil {
		return fmt.Errorf("transaction_sign: malformed Value: %w", err)
	}
	switch v.Method {
	case "eth_sendTransaction":
		// EvmTransaction was attached separately on req.Transaction
		// at emit time — use that for signing so we keep the
		// existing SignAndSend path (handles save + broadcast +
		// fee backfill).
		if req.Transaction == nil {
			return errors.New("eth_sendTransaction approval missing transaction")
		}
		return req.Transaction.SignAndSend(e, keys)
	case "solana_signTransaction":
		return approveSolanaSignTx(ctx, e, req, keys, v.Raw, false)
	case "solana_signAndSendTransaction":
		return approveSolanaSignTx(ctx, e, req, keys, v.Raw, true)
	case "mpurse_signRawTransaction":
		return approveMpurseSignRawTx(ctx, e, req, keys, v.Raw)
	default:
		return fmt.Errorf("transaction_sign: unknown method %q", v.Method)
	}
}

// approveMessageSign drives the chain-specific signer for any
// "message_sign" approval.
func approveMessageSign(ctx context.Context, e *env, req *request, keys []*wltsign.KeyDescription) error {
	if len(keys) == 0 {
		return errors.New("message_sign approval requires Keys")
	}
	v, err := decodeMsgSignValue(req.Value)
	if err != nil {
		return fmt.Errorf("message_sign: malformed Value: %w", err)
	}
	switch v.Method {
	case "personal_sign":
		return approveEthPersonalSign(ctx, e, req, keys, v)
	case "eth_signTypedData", "eth_signTypedData_v3", "eth_signTypedData_v4":
		return approveEthTypedDataSign(ctx, e, req, keys, v)
	case "solana_signMessage":
		return approveSolanaSignMessage(ctx, e, req, keys, v)
	case "mpurse_signMessage":
		return approveMpurseSignMessage(ctx, e, req, keys, v)
	default:
		return fmt.Errorf("message_sign: unknown method %q", v.Method)
	}
}

// ── Decoders ─────────────────────────────────────────────────

func decodeTxSignValue(v any) (*TransactionSignValue, error) {
	if v == nil {
		return nil, errors.New("nil Value")
	}
	buf, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := &TransactionSignValue{}
	if err := json.Unmarshal(buf, out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeMsgSignValue(v any) (*MessageSignValue, error) {
	if v == nil {
		return nil, errors.New("nil Value")
	}
	buf, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := &MessageSignValue{}
	if err := json.Unmarshal(buf, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ── EVM message signers ──────────────────────────────────────

func approveEthPersonalSign(ctx context.Context, e *env, req *request, keys []*wltsign.KeyDescription, v *MessageSignValue) error {
	msg, err := base64.StdEncoding.DecodeString(v.MessageBytes)
	if err != nil {
		return fmt.Errorf("decode message bytes: %w", err)
	}
	full := append([]byte("\x19Ethereum Signed Message:\n"), []byte(strconv.Itoa(len(msg)))...)
	full = append(full, msg...)
	digest := cryptutil.Hash(full, sha3.NewLegacyKeccak256)
	a, err := wltacct.FindAccount(e, *req.Account)
	if err != nil {
		return fmt.Errorf("could not find account for signature: %w", err)
	}
	signOpt := &wltsign.Opts{Context: ctx, IL: a.IL, Keys: keys}
	// Ethereum wire format (R || S || V, V ∈ {27, 28}). The previous
	// "hex(a.Sign(...))" path returned DER, which ecrecover and every
	// off-chain verifier (viem, ethers, OpenSea, Snapshot, Permit2)
	// rejected as an invalid signature.
	sig, err := a.SignEthereumDigest(digest, signOpt)
	if err != nil {
		return fmt.Errorf("signature failed: %w", err)
	}
	str := "0x" + hex.EncodeToString(sig)
	req.Result = &str
	return nil
}

func approveEthTypedDataSign(ctx context.Context, e *env, req *request, keys []*wltsign.KeyDescription, v *MessageSignValue) error {
	if v.StructuredData == nil {
		return errors.New("typed-data approval missing structured payload")
	}
	tdJSON, err := json.Marshal(v.StructuredData)
	if err != nil {
		return fmt.Errorf("re-marshal typed data: %w", err)
	}
	td, err := ParseEIP712TypedData(string(tdJSON))
	if err != nil {
		return fmt.Errorf("failed to parse EIP-712 data: %w", err)
	}
	digest, err := td.HashEIP712()
	if err != nil {
		return fmt.Errorf("failed to compute EIP-712 hash: %w", err)
	}
	a, err := wltacct.FindAccount(e, *req.Account)
	if err != nil {
		return fmt.Errorf("could not find account for signature: %w", err)
	}
	signOpt := &wltsign.Opts{Context: ctx, IL: a.IL, Keys: keys}
	sig, err := a.SignEthereumDigest(digest, signOpt)
	if err != nil {
		return fmt.Errorf("EIP-712 signature failed: %w", err)
	}
	str := "0x" + hex.EncodeToString(sig)
	req.Result = &str
	return nil
}

// ── Solana signers ───────────────────────────────────────────

func approveSolanaSignMessage(ctx context.Context, _ *env, req *request, keys []*wltsign.KeyDescription, v *MessageSignValue) error {
	msg, err := base64.StdEncoding.DecodeString(v.MessageBytes)
	if err != nil {
		return fmt.Errorf("decode message: %w", err)
	}
	a, err := wltacct.FindAccount(getEnvFromCtx(ctx), *req.Account)
	if err != nil {
		return fmt.Errorf("could not find account: %w", err)
	}
	_, _ = wltacct.EnsureEd25519PubkeyOnAccount(ctx, a, keys)
	signOpt := &wltsign.Opts{Context: ctx, Keys: keys}
	sig, err := a.Sign(nil, msg, signOpt)
	if err != nil {
		return fmt.Errorf("solana sign failed: %w", err)
	}
	req.Result = map[string]any{
		"signature": base58.Bitcoin.Encode(sig),
		"publicKey": a.Address,
	}
	return nil
}

func approveSolanaSignTx(ctx context.Context, _ *env, req *request, keys []*wltsign.KeyDescription, rawB64 string, broadcast bool) error {
	txBytes, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return fmt.Errorf("decode transaction: %w", err)
	}
	a, err := wltacct.FindAccount(getEnvFromCtx(ctx), *req.Account)
	if err != nil {
		return fmt.Errorf("could not find account: %w", err)
	}
	_, _ = wltacct.EnsureEd25519PubkeyOnAccount(ctx, a, keys)
	msg, err := solanaExtractMessage(txBytes)
	if err != nil {
		return err
	}
	signOpt := &wltsign.Opts{Context: ctx, Keys: keys}
	sig, err := a.Sign(nil, msg, signOpt)
	if err != nil {
		return fmt.Errorf("solana sign failed: %w", err)
	}
	signed := solanaInsertSignature(txBytes, sig)
	if !broadcast {
		req.Result = map[string]any{"transaction": base64.StdEncoding.EncodeToString(signed)}
		return nil
	}
	envObj := wltintf.GetEnv(ctx)
	if envObj == nil {
		return errors.New("failed to get env")
	}
	net, err := wltnet.CurrentNetwork(envObj)
	if err != nil {
		return err
	}
	txB58 := base58.Bitcoin.Encode(signed)
	result, err := net.DoRPC("sendTransaction", txB58, map[string]any{"encoding": "base58"})
	if err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}
	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return fmt.Errorf("failed to parse transaction hash: %w", err)
	}
	wltintf.NotifyTxBroadcast(envObj)
	req.Result = map[string]any{"signature": txHash}
	return nil
}

// ── Mpurse (Bitcoin-family) signers ──────────────────────────

func approveMpurseSignMessage(ctx context.Context, e *env, req *request, keys []*wltsign.KeyDescription, v *MessageSignValue) error {
	msg, err := base64.StdEncoding.DecodeString(v.MessageBytes)
	if err != nil {
		return fmt.Errorf("decode message: %w", err)
	}
	a, err := wltacct.FindAccount(e, *req.Account)
	if err != nil {
		return fmt.Errorf("could not find account: %w", err)
	}
	n, err := wltnet.CurrentNetwork(e)
	if err != nil {
		return fmt.Errorf("no current network: %w", err)
	}
	prefix, ok := wltacct.BitcoinMessagePrefix(n.ChainId)
	if !ok {
		return fmt.Errorf("no Bitcoin-family message prefix known for chain %q", n.ChainId)
	}
	signOpt := &wltsign.Opts{Context: ctx, IL: a.IL, Keys: keys}
	sig, err := a.SignBitcoinMessage(prefix, msg, signOpt)
	if err != nil {
		return fmt.Errorf("mpurse message sign failed: %w", err)
	}
	b64 := base64.StdEncoding.EncodeToString(sig)
	req.Result = &b64
	return nil
}

func approveMpurseSignRawTx(ctx context.Context, e *env, req *request, keys []*wltsign.KeyDescription, rawHex string) error {
	rawTx, err := hex.DecodeString(rawHex)
	if err != nil {
		return fmt.Errorf("decode tx hex: %w", err)
	}
	a, err := wltacct.FindAccount(e, *req.Account)
	if err != nil {
		return fmt.Errorf("could not find account: %w", err)
	}
	n, err := wltnet.CurrentNetwork(e)
	if err != nil {
		return fmt.Errorf("no current network: %w", err)
	}
	signed, err := wlttx.SignRawBitcoinTx(&wlttx.SignContext{Env: e}, a, n, rawTx, keys)
	if err != nil {
		return fmt.Errorf("mpurse tx sign failed: %w", err)
	}
	out := hex.EncodeToString(signed)
	req.Result = &out
	_ = ctx
	return nil
}

// getEnvFromCtx pulls *env out of an apirouter context — Solana
// signers don't take an *env directly because their original case
// statements grabbed it via wltintf.GetEnv.
func getEnvFromCtx(ctx context.Context) wltintf.Env {
	if ac, ok := ctx.(*apirouter.Context); ok {
		if e := apirouter.GetObject[env](ac, "@env"); e != nil {
			return e
		}
	}
	return wltintf.GetEnv(ctx)
}
