package wlttx

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltquote"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

type Transaction struct {
	psql.Name    `sql:"Transaction"`
	Id           *xuid.XUID                `json:"id,omitempty" sql:",key=PRIMARY"`
	Type         string                    `json:"type" sql:",type=VARCHAR,size=255"`           // transfer, etc
	Asset        string                    `json:"asset" sql:",type=VARCHAR,size=255"`          // asset id (network id + "@" + NATIVE if native, or token id)
	From         string                    `json:"from,omitempty" sql:",type=VARCHAR,size=255"` // from (account)
	To           string                    `json:"to" sql:",type=VARCHAR,size=255"`
	Gas          uint64                    `json:"gas" sql:",type=BIGINT"`                          // gas amount
	GasPrice     string                    `json:"gasPrice,omitempty" sql:",type=VARCHAR,size=255"` // gas price
	Fee          *wltobj.Amount            `json:"fee,omitempty" sql:",type=JSON,format=json"`
	Nonce        uint64                    `json:"nonce" sql:",type=BIGINT"`                      // eth only
	Format       string                    `json:"format,omitempty" sql:",type=VARCHAR,size=255"` // transaction format, for ethereum: legacy or eip1559
	Raw          []byte                    `json:"raw,omitempty" sql:",type=BLOB"`
	Hash         string                    `json:"hash,omitempty" sql:",type=VARCHAR,size=255"`
	URL          string                    `json:"url,omitempty" sql:",type=TEXT"`
	Network      *xuid.XUID                `json:"network,omitempty" sql:",type=VARCHAR,size=255"`
	Amount       *wltobj.Amount            `json:"amount" sql:",type=JSON,format=json"`
	Value        *wltobj.Amount            `json:"value,omitempty" sql:",type=JSON,format=json"`
	Data         string                    `json:"data,omitempty" sql:",type=TEXT"`
	Keys         []*wltsign.KeyDescription `json:"Keys,omitempty" sql:"-"`
	Created      *time.Time                `json:"created,omitempty" sql:",type=DATETIME"`
	FiatAmount   *wltobj.Amount            `json:"fiat_amount,omitempty" sql:"-"`
	FiatCurrency string                    `json:"fiat_currency,omitempty" sql:"-"`
	FiatQuote    any                       `json:"fiat_quote,omitempty" sql:"-"`
}

func (tx *Transaction) save(e wltintf.Env) error {
	if tx.Id == nil {
		var err error
		tx.Id, err = xuid.NewRandom("tx")
		if err != nil {
			return err
		}
	}

	return psql.Replace(e, tx)
}

func (tx *Transaction) getNetwork(e wltintf.Env) (*wltnet.Network, error) {
	if tx.Network != nil {
		return wltnet.NetworkById(e, tx.Network)
	} else {
		n, err := wltnet.CurrentNetwork(e)
		if err != nil {
			return nil, err
		}
		tx.Network = n.Id
		return n, nil
	}
}

func (tx *Transaction) getSymbol(e wltintf.Env) (string, error) {
	// a.Asset = evm.137.NATIVE
	// TODO For now we only do native assets anyway, return network symbol
	net, err := tx.getNetwork(e)
	if err != nil {
		return "", err
	}
	return net.NativeSymbol()
}

func (tx *Transaction) convertTo(e wltintf.Env, currency string) error {
	symbol, err := tx.getSymbol(e)
	if err != nil {
		return err
	}
	quote, err := wltquote.GetQuotesForToken(e, symbol)
	if err != nil {
		return err
	}
	info, ok := quote.Quote[currency]
	if !ok {
		return fs.ErrNotExist
	}
	// ok we have a price now in info.Price, it's a float so let's first convert it to a wltobj.Amount
	price, _ := wltobj.NewAmountFromFloat64(info.Price, 8) // more decimals always good
	// multiply
	var amt *wltobj.Amount
	if tx.Amount != nil && tx.Amount.Sign() > 0 {
		amt = tx.Amount
	} else if tx.Value != nil && tx.Value.Sign() > 0 {
		amt = tx.Value
	}
	if amt != nil {
		tx.FiatAmount = wltobj.NewAmount(0, 8).Mul(amt, price)
		tx.FiatCurrency = currency
		tx.FiatQuote = info
	}
	return nil
}

func (tx *Transaction) encodeTx(n *wltnet.Network, acct *wltacct.Account, csigner crypto.Signer, signopts crypto.SignerOpts) (*outscript.EvmTx, error) {
	switch tx.Type {
	case "transfer", "evm":
		switch tx.Format {
		case "legacy":
			fallthrough
		default:
			v, ok := new(big.Int).SetString(tx.GasPrice, 0)
			if !ok {
				return nil, errors.New("invalid gasPrice")
			}
			info, err := n.GetChainInfo()
			if err != nil {
				return nil, err
			}
			res := &outscript.EvmTx{
				Type:      outscript.EvmTxLegacy,
				Nonce:     tx.Nonce,
				GasFeeCap: v,
				Gas:       tx.Gas,
				To:        tx.To,
				ChainId:   info.ChainId,
			}
			if tx.Value != nil && tx.Value.Sign() > 0 {
				res.Value = tx.Value.Value()
			} else if tx.Amount != nil {
				res.Value = tx.Amount.Value()
			}
			if data := tx.Data; data != "" {
				if data, ok := strings.CutPrefix(data, "0x"); ok {
					dataBin, err := hex.DecodeString(data)
					if err != nil {
						return nil, err
					}
					res.Data = dataBin
				} else {
					return nil, errors.New("bad tx.Data: must start with 0x or be empty")
				}
			}
			err = res.SignWithOptions(csigner, signopts)
			return res, err
		}
	default:
	}
	return nil, errors.New("TODO")
}

func (tx *Transaction) estimateGas(n *wltnet.Network) error {
	v := make(map[string]any)
	if tx.Data != "" {
		v["data"] = tx.Data
	}
	if tx.Amount != nil && tx.Amount.Sign() > 0 {
		v["value"] = "0x" + tx.Amount.Value().Text(16)
	} else if tx.Value != nil && tx.Value.Sign() > 0 {
		v["value"] = "0x" + tx.Value.Value().Text(16)
	}
	if tx.To != "" {
		v["to"] = tx.To
	}

	log.Printf("about to run eth_estimateGas with: %+v", v)

	gas, err := ethrpc.ReadUint64(n.DoRPC("eth_estimateGas", v))
	if err != nil {
		return err
	}
	tx.Gas = gas
	return nil
}

func (tx *Transaction) Validate(e wltintf.Env) error {
	if tx == nil {
		return errors.New("error: nil tx")
	}
	switch tx.Type {
	case "transfer": // transfer of an Asset
		if tx.Amount.Sign() <= 0 {
			return errors.New("invalid amount")
		}
		if tx.Asset == "" {
			return errors.New("asset is required")
		}
	case "solana_transfer", "solana_spl_transfer":
		if tx.Amount.Sign() <= 0 {
			return errors.New("invalid amount")
		}
	case "evm": // evm raw transaction (for example as sent via eth_sendTransaction)
		// OK
	default:
		return fmt.Errorf("unsupported transaction type %s", tx.Type)
	}

	var acct *wltacct.Account
	var err error

	if tx.From == "" {
		acct, err = wltacct.CurrentAccount(e)
		if err != nil {
			return err
		}
		tx.From = acct.Address
	} else {
		acct, err = wltacct.FindAccount(e, tx.From)
		if err != nil {
			return err
		}
		tx.From = acct.Address
	}

	n, err := tx.getNetwork(e)
	if err != nil {
		return err
	}
	tx.Network = n.Id

	if n.Type == "solana" {
		// Solana has fixed fees (~5000 lamports)
		tx.Fee = wltobj.NewAmountRaw(big.NewInt(5000), 9)
		return nil
	}

	// EVM-specific validation
	if tx.Nonce == 0 {
		txc, err := ethrpc.ReadUint64(n.DoRPC("eth_getTransactionCount", acct.Address, "pending"))
		if err != nil {
			return err
		}
		tx.Nonce = txc
	}

	if tx.Gas == 0 {
		err := tx.estimateGas(n)
		if err != nil {
			return err
		}
	}

	if tx.GasPrice == "" {
		v, err := ethrpc.ReadBigInt(n.DoRPC("eth_gasPrice"))
		if err != nil {
			return err
		}
		tx.GasPrice = v.String()
	}

	tx.computeFee(n)

	if tx.Format == "" {
		// TODO check ChainInfo.HasFeature("EIP1559")
		tx.Format = "legacy"
	}
	return nil
}

func (tx *Transaction) computeFee(n *wltnet.Network) error {
	// fee = gas*gasPrice
	info, err := n.GetChainInfo()
	if err != nil {
		return err
	}

	gp, ok := new(big.Int).SetString(tx.GasPrice, 0)
	if !ok {
		return errors.New("invalid gasprice")
	}

	amt := wltobj.NewAmountRaw(gp, info.NativeCurrency.Decimals)
	gas := wltobj.NewAmount(int64(tx.Gas), 0)
	tx.Fee = amt.Dup().Mul(amt, gas)
	return nil
}

func (tx *Transaction) ApiDelete(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	_, err := psql.ForceDelete[Transaction](e, map[string]any{"Id": tx.Id})
	return err
}

func (tx *Transaction) SignAndSend(ctx context.Context, keys []*wltsign.KeyDescription) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	var acct *wltacct.Account
	var err error

	if tx.From == "" {
		return errors.New("from is required")
	}
	acct, err = wltacct.FindAccount(e, tx.From)
	if err != nil {
		return err
	}

	n, err := tx.getNetwork(e)
	if err != nil {
		return err
	}

	now := time.Now()
	tx.Created = &now

	if keys == nil {
		keys = tx.Keys
	}
	if keys == nil {
		return errors.New("keys are missing")
	}
	tx.Keys = nil // always set to nil

	if n.Type == "solana" {
		err = tx.signAndSendSolana(ctx, n, acct, keys)
		if err != nil {
			return err
		}
		return tx.save(e)
	}

	signOpt := &wltsign.Opts{
		Context: ctx,
		IL:      acct.IL,
		Keys:    keys,
	}

	data, err := tx.encodeTx(n, acct, acct, signOpt)
	if err != nil {
		return err
	}
	// sets: tx.Hash = hex.EncodeToString(h[:])
	// return secp256k1.Sign(digestHash, seckey)
	buf, err := data.MarshalBinary()
	if err != nil {
		return err
	}
	tx.Raw = buf

	err = tx.save(e)
	if err != nil {
		return err
	}

	// eth_sendRawTransaction
	hash, err := ethrpc.ReadString(n.DoRPC("eth_sendRawTransaction", "0x"+hex.EncodeToString(buf)))
	if err != nil {
		return err
	}
	// should already be the same
	tx.Hash = hash
	tx.URL = n.TransactionUrl(tx.Hash)
	if err := tx.save(e); err != nil {
		return fmt.Errorf("failed to save transaction after broadcast: %w", err)
	}

	return nil
}
