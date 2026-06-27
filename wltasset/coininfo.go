package wltasset

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
)

// https://ws.atonline.com/_special/rest/Crypto/DataCache:ccInfo?key_type=symbol&key=MATIC&pretty
type CoinInfo struct {
	Id        int                 `json:"id"`
	Name      string              `json:"name"`
	Symbol    string              `json:"symbol"`
	Category  string              `json:"category"`
	Logo      string              `json:"logo"` // data:image/png;base64,...
	Subreddit string              `json:"subreddit"`
	Notice    string              `json:"notice"`
	URLs      map[string][]string `json:"urls"`
	Twitter   string              `json:"twitter_username"`
}

type coinInfoApiResponse struct {
	Result string    `json:"result"` // "success"
	Data   *CoinInfo `json:"data"`
}

func CoinInfoBySymbol(e wltintf.Env, symbol string) (*CoinInfo, error) {
	u := "https://ws.atonline.com/_special/rest/Crypto/DataCache:ccInfo?key_type=symbol&key=" + url.QueryEscape(symbol)
	return coinInfoByUrl(e, u)
}

func CoinInfoByAddress(e wltintf.Env, addr string) (*CoinInfo, error) {
	u := "https://ws.atonline.com/_special/rest/Crypto/DataCache:ccInfo?key_type=address&key=" + url.QueryEscape(addr)
	return coinInfoByUrl(e, u)
}

func coinInfoByUrl(e wltintf.Env, u string) (*CoinInfo, error) {
	buf, err := e.CacheGet(context.Background(), u, 10*time.Second, 7*24*time.Hour)
	if err != nil {
		return nil, err
	}

	var ci *coinInfoApiResponse
	if err = json.Unmarshal(buf, &ci); err != nil {
		return nil, err
	}
	// A valid-but-null JSON body (e.g. `null`) unmarshals into a nil
	// pointer without error — guard before dereferencing.
	if ci == nil {
		return nil, nil
	}
	return ci.Data, nil
}
