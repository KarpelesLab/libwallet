package wltasset

import (
	"io/fs"
	"time"

	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltquote"
	"github.com/KarpelesLab/xuid"
)

type Asset struct {
	Id           *xuid.XUID        `json:"id,omitempty" gorm:"primaryKey"`
	Key          string            `json:"key" gorm:"index:Key,unique"`
	Name         string            `json:"name"`
	Symbol       string            `json:"symbol"`
	Amount       *wltobj.Amount `json:"amount" gorm:"serializer:json"`
	Info         *CoinInfo         `json:"info" gorm:"-:all"`
	Type         string            `json:"type"`
	Network      *xuid.XUID        `json:"network,omitempty"`
	FiatAmount   *wltobj.Amount `json:"fiat_amount,omitempty" gorm:"-:all"`
	FiatCurrency string            `json:"fiat_currency,omitempty" gorm:"-:all"`
	FiatQuote    any               `json:"fiat_quote,omitempty" gorm:"-:all"`
	TestNet      bool              `json;"testnet,omitempty" gorm:"-:all"`
	Created      time.Time         `gorm:"autoCreateTime"`
	Updated      time.Time         `gorm:"autoUpdateTime"`
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
