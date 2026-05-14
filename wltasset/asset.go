package wltasset

import (
	"io/fs"
	"strings"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltquote"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

// nativeKeySuffix is libwallet's canonical "native asset" sentinel —
// the suffix on Asset.Key for native ETH / SOL / BTC balances. Tokens
// end with their on-chain contract / mint address instead.
//
// Single source of truth shared by [Asset.IsNative], [Asset.TokenAddress],
// and the various .NATIVE-aware callers in wltnet / wlttx / wltbase.
const nativeKeySuffix = ".NATIVE"

type Asset struct {
	TableName    psql.Name      `sql:"Asset"`
	Id           *xuid.XUID     `json:"id,omitempty" sql:",key=PRIMARY"`
	Key          string         `json:"key" sql:",type=VARCHAR,size=255,key=UNIQUE:Key"`
	Name         string         `json:"name" sql:",type=VARCHAR,size=255"`
	Symbol       string         `json:"symbol" sql:",type=VARCHAR,size=255"`
	Amount       *wltobj.Amount `json:"amount" sql:",type=JSON,format=json"`
	Info         *CoinInfo      `json:"info" sql:"-"`
	Type         string         `json:"type" sql:",type=VARCHAR,size=255"`
	Network      *xuid.XUID     `json:"network,omitempty" sql:",type=VARCHAR,size=255"`
	FiatAmount   *wltobj.Amount `json:"fiat_amount,omitempty" sql:"-"`
	FiatCurrency string         `json:"fiat_currency,omitempty" sql:"-"`
	FiatQuote    any            `json:"fiat_quote,omitempty" sql:"-"`
	TestNet      bool           `json:"testnet,omitempty" sql:"-"`
	Created      time.Time      `sql:",type=DATETIME"`
	Updated      time.Time      `sql:",type=DATETIME"`
}

// IsNative reports whether this Asset is the chain's native currency
// (ETH / SOL / BTC / etc.) by checking the canonical `.NATIVE` suffix
// on [Asset.Key]. The Asset.Type field is "fungible" for both native
// and tokens and is not a reliable native-vs-token discriminator.
func (a *Asset) IsNative() bool {
	if a == nil {
		return false
	}
	return strings.HasSuffix(a.Key, nativeKeySuffix)
}

// TokenAddress returns the on-chain mint / contract part of
// [Asset.Key], or the empty string for native assets and for keys
// that don't match the `"<type>.<chainId>.<address>"` convention.
//
// For "evm.1.0xA0b86991…" returns "0xA0b86991…"; for
// "solana.mainnet.EPjFW…" returns "EPjFW…"; for "evm.1.NATIVE"
// returns "".
func (a *Asset) TokenAddress() string {
	if a == nil || a.IsNative() {
		return ""
	}
	idx := strings.LastIndexByte(a.Key, '.')
	if idx < 0 || idx == len(a.Key)-1 {
		return ""
	}
	return a.Key[idx+1:]
}

func (a *Asset) ConvertTo(e wltintf.Env, currency string) error {
	if a.TestNet {
		// do not perform conversion on anything related to a testnet
		return nil
	}
	quote, err := wltquote.GetQuotesForToken(e, a.Symbol)
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
	a.FiatAmount = wltobj.NewAmount(0, 8).Mul(a.Amount, price)
	a.FiatCurrency = currency
	a.FiatQuote = info
	return nil
}
