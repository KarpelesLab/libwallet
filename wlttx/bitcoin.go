package wlttx

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/libwallet/wltwallet"
	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/secp256k1"
)

// walletByAccount fetches the wallet associated with an account.
func walletByAccount(e wltintf.Env, a *wltacct.Account) (*wltwallet.Wallet, error) {
	return wltwallet.WalletById(e, a.Wallet)
}

// bitcoinTxo is one entry in the modchain_lookupTxoBIP32 response.
//
// modchain serializes Bitcoin amounts via outscript.BtcAmount, which
// marshals to a decimal string (e.g. "0.00000001"). The BtcAmount
// type's UnmarshalJSON handles both decimal and integer forms.
type bitcoinTxo struct {
	Txo    string             `json:"txo"` // "<txid>:<vout>"
	Height int64              `json:"height"`
	Amt    outscript.BtcAmount `json:"amt"` // satoshi, decoded from "0.00000001" form
	I      int                `json:"i"`      // child index under the scan path
	Script string             `json:"script"` // flavor: p2pkh, p2wpkh, etc
}

type bitcoinTxoResp struct {
	Txo     []bitcoinTxo        `json:"txo"`
	Balance outscript.BtcAmount `json:"balance"`
	LastI   int                 `json:"lastI"`
}

// buildBitcoinTx assembles and signs a Bitcoin-family transaction for
// tx.Type == "bitcoin_transfer". On success it sets tx.Raw, tx.Hash, tx.Fee.
func buildBitcoinTx(ctx *SignContext, tx *Transaction, n *wltnet.Network, acct *wltacct.Account, keys []*wltsign.KeyDescription) error {
	if tx.Amount == nil || tx.Amount.Sign() <= 0 {
		return errors.New("invalid amount")
	}
	if tx.To == "" {
		return errors.New("recipient (To) is required")
	}

	xpub, err := acct.Xpub()
	if err != nil {
		return fmt.Errorf("xpub: %w", err)
	}

	// 1. Fetch unspent UTXOs from the receive chain
	utxos, err := fetchBitcoinUTXOs(n, xpub, "m/0")
	if err != nil {
		return err
	}
	if len(utxos.Txo) == 0 {
		return errors.New("no spendable UTXOs")
	}

	// 2. Parse recipient
	recipientOut, err := outscript.ParseBitcoinBasedAddress(bitcoinNetworkName(n.ChainId), tx.To)
	if err != nil {
		return fmt.Errorf("parse recipient address: %w", err)
	}

	// 3. Coin selection (greedy — simple but effective)
	wantSats := tx.Amount.Value().Int64()
	// Fee estimation: modchain exposes fee via JSON-RPC; fall back to a
	// conservative estimate based on tx size if the RPC call fails.
	feeRateSatPerVB, err := bitcoinFeeRate(n)
	if err != nil {
		feeRateSatPerVB = 10 // conservative fallback
	}

	selected, totalIn, err := selectUTXOs(utxos.Txo, wantSats, feeRateSatPerVB)
	if err != nil {
		return err
	}

	// 4. Derive next change address (m/1/{lastChangeI+1})
	changeUtxos, err := fetchBitcoinUTXOs(n, xpub, "m/1")
	changeIndex := 0
	if err == nil {
		changeIndex = changeUtxos.LastI + 1
	}
	changeAddr, err := acct.ChangeAddress(n.ChainId, changeIndex)
	if err != nil {
		return fmt.Errorf("derive change address: %w", err)
	}
	changeOut, err := outscript.ParseBitcoinBasedAddress(bitcoinNetworkName(n.ChainId), changeAddr)
	if err != nil {
		return fmt.Errorf("parse change address: %w", err)
	}

	// 5. Build the transaction
	btx := &outscript.BtcTx{Version: 2}
	for _, u := range selected {
		txid, vout, err := parseTxoRef(u.Txo)
		if err != nil {
			return err
		}
		var hex32 outscript.Hex32
		copy(hex32[:], txid)
		btx.In = append(btx.In, &outscript.BtcTxInput{
			TXID:     hex32,
			Vout:     vout,
			Sequence: 0xfffffffd, // RBF-enabled
		})
	}

	// Output to recipient
	btx.Out = append(btx.Out, &outscript.BtcTxOutput{
		Amount: outscript.BtcAmount(wantSats),
		Script: recipientOut.Bytes(),
	})

	// Compute size-based fee, then derive change
	estVSize := estimateTxVSize(len(selected), 2) // send + change
	fee := int64(estVSize) * feeRateSatPerVB
	change := totalIn - wantSats - fee
	if change < 0 {
		return fmt.Errorf("insufficient funds: have %d sats, need %d + fee %d", totalIn, wantSats, fee)
	}

	// Dust threshold: ~546 sats for p2pkh, skip change below that
	if change > 546 {
		btx.Out = append(btx.Out, &outscript.BtcTxOutput{
			Amount: outscript.BtcAmount(change),
			Script: changeOut.Bytes(),
		})
	} else {
		// Give dust to miners
		fee += change
		change = 0
	}

	// 6. Build signers for each input
	sighash := uint32(1) // SIGHASH_ALL
	if n.ChainId == "bitcoin-cash" {
		sighash = 0x41 // SIGHASH_ALL | SIGHASH_FORKID
	}

	signers := make([]*outscript.BtcTxSign, len(selected))
	for i, u := range selected {
		signer, err := newBtcInputSigner(ctx, acct, 0 /*receive*/, u.I, keys)
		if err != nil {
			return fmt.Errorf("new signer for input %d: %w", i, err)
		}
		scheme := u.Script // p2wpkh, p2pkh, etc
		signers[i] = &outscript.BtcTxSign{
			Key:     signer,
			Scheme:  scheme,
			Amount:  u.Amt,
			SigHash: sighash,
		}
	}

	if err := btx.Sign(signers...); err != nil {
		return fmt.Errorf("tx sign: %w", err)
	}

	// 7. Serialize and store
	rawBytes, err := btx.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal tx: %w", err)
	}
	tx.Raw = rawBytes
	tx.Fee = wltobj.NewAmountRaw(big.NewInt(fee), 8)
	return nil
}

// broadcastBitcoinTx sends the raw transaction via sendrawtransaction.
func broadcastBitcoinTx(tx *Transaction, n *wltnet.Network) error {
	if len(tx.Raw) == 0 {
		return errors.New("empty raw tx")
	}
	hexRaw := hex.EncodeToString(tx.Raw)
	raw, err := n.DoRPC("sendrawtransaction", hexRaw)
	if err != nil {
		return fmt.Errorf("sendrawtransaction: %w", err)
	}
	var txid string
	if err := json.Unmarshal(raw, &txid); err != nil {
		return fmt.Errorf("parse sendrawtransaction response: %w", err)
	}
	tx.Hash = txid
	tx.URL = n.TransactionUrl(txid)
	return nil
}

// ── helpers ────────────────────────────────────────────────────────────────

// SignContext is the minimal context needed by buildBitcoinTx. Exported for
// wlttx use; we wrap it so the function signature is stable.
type SignContext struct {
	Env wltintf.Env
}

func fetchBitcoinUTXOs(n *wltnet.Network, xpub, path string) (*bitcoinTxoResp, error) {
	raw, err := n.DoRPC("modchain_lookupTxoBIP32", xpub, path, true)
	if err != nil {
		return nil, fmt.Errorf("modchain_lookupTxoBIP32: %w", err)
	}
	var resp bitcoinTxoResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse txo response: %w", err)
	}
	return &resp, nil
}

func bitcoinFeeRate(n *wltnet.Network) (int64, error) {
	raw, err := n.DoRPC("estimatesmartfee", 6)
	if err != nil {
		return 0, err
	}
	var resp struct {
		FeeRate float64 `json:"feerate"` // BTC/kB
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return 0, err
	}
	// Convert BTC/kB → sat/vB
	satPerVB := int64(resp.FeeRate * 1e8 / 1000)
	if satPerVB < 1 {
		satPerVB = 1
	}
	return satPerVB, nil
}

// selectUTXOs does naive greedy coin selection. Returns selected UTXOs and
// their total input amount. Does not fee-bump iteratively; caller recomputes
// fee based on selected input count.
func selectUTXOs(all []bitcoinTxo, wantSats, feeRatePerVB int64) ([]bitcoinTxo, int64, error) {
	// Sort largest first (mutate a copy)
	utxos := make([]bitcoinTxo, len(all))
	copy(utxos, all)
	// Insertion sort works fine for typical wallet sizes
	for i := 1; i < len(utxos); i++ {
		for j := i; j > 0 && utxos[j-1].Amt < utxos[j].Amt; j-- {
			utxos[j-1], utxos[j] = utxos[j], utxos[j-1]
		}
	}

	var total int64
	var out []bitcoinTxo
	for _, u := range utxos {
		out = append(out, u)
		total += int64(u.Amt)
		estFee := int64(estimateTxVSize(len(out), 2)) * feeRatePerVB
		if total >= wantSats+estFee {
			return out, total, nil
		}
	}
	return nil, 0, fmt.Errorf("insufficient funds: have %d sats across %d utxos", total, len(out))
}

// estimateTxVSize returns a rough vsize estimate for a p2wpkh transaction
// with the given number of inputs and outputs. Conservative.
func estimateTxVSize(ins, outs int) int {
	// p2wpkh segwit: input ~68 vbytes, output ~31 vbytes, overhead ~11
	return 11 + ins*68 + outs*31
}

func parseTxoRef(ref string) ([]byte, uint32, error) {
	parts := strings.Split(ref, ":")
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid txo ref %q", ref)
	}
	txid, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, 0, fmt.Errorf("invalid txid hex: %w", err)
	}
	if len(txid) != 32 {
		return nil, 0, fmt.Errorf("txid must be 32 bytes, got %d", len(txid))
	}
	// Reverse the txid: Bitcoin stores txids little-endian on the wire
	rev := make([]byte, 32)
	for i := 0; i < 32; i++ {
		rev[i] = txid[31-i]
	}
	var vout uint32
	if _, err := fmt.Sscanf(parts[1], "%d", &vout); err != nil {
		return nil, 0, fmt.Errorf("invalid vout: %w", err)
	}
	return rev, vout, nil
}

func bitcoinNetworkName(chainId string) string {
	switch chainId {
	case "bitcoin":
		return "bitcoin"
	case "bitcoin-cash":
		return "bitcoincash"
	case "litecoin":
		return "litecoin"
	case "dogecoin":
		return "dogecoin"
	default:
		return "auto"
	}
}

// ── per-input TSS signer ────────────────────────────────────────────────────

// btcInputSigner implements crypto.Signer for a single BTC input. It derives
// the child public key at m/{chain}/{index} relative to the account's chaincode
// and uses the account's wallet (with cumulative IL) to produce a real
// TSS signature.
type btcInputSigner struct {
	ctx      *SignContext
	acct     *wltacct.Account
	childIL  *big.Int
	childPub *secp256k1.PublicKey
	keys     []*wltsign.KeyDescription
}

func newBtcInputSigner(ctx *SignContext, acct *wltacct.Account, chain, index int, keys []*wltsign.KeyDescription) (*btcInputSigner, error) {
	ccBytes, err := base64.RawURLEncoding.DecodeString(acct.Chaincode)
	if err != nil {
		return nil, fmt.Errorf("chaincode: %w", err)
	}
	childIL, childPub, err := wltacct.DerivePublicKey(acct.PublicKey(), ccBytes, fmt.Sprintf("m/%d/%d", chain, index))
	if err != nil {
		return nil, fmt.Errorf("derive child: %w", err)
	}

	// Combine with account's own IL (if any) since the wallet signs from
	// the wallet root, and the account's IL is the first hop. We need the
	// TOTAL IL from wallet root to this specific child.
	finalIL := new(big.Int)
	if acct.IL != nil {
		finalIL.Add(finalIL, acct.IL)
	}
	finalIL.Add(finalIL, childIL)
	// Modular reduction happens inside TSS signing

	return &btcInputSigner{
		ctx:      ctx,
		acct:     acct,
		childIL:  finalIL,
		childPub: childPub,
		keys:     keys,
	}, nil
}

func (s *btcInputSigner) Public() crypto.PublicKey {
	// Return an *ecdsa.PublicKey (what outscript expects to generate scripts)
	return &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     s.childPub.X(),
		Y:     s.childPub.Y(),
	}
}

func (s *btcInputSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Delegate to the wallet with our custom combined IL.
	w, err := walletByAccount(s.ctx.Env, s.acct)
	if err != nil {
		return nil, err
	}
	aopts := &wltsign.Opts{
		Context: s.ctx.Env,
		IL:      s.childIL,
		Keys:    s.keys,
	}
	return w.Sign(rand, digest, aopts)
}
