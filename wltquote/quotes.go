package wltquote

import (
	"context"
	"io/fs"
	"sync"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pjson"
	"github.com/KarpelesLab/rest"
)

var (
	cachedQuoteData    []*CMCQuoteData
	cachedQuoteDataLk  sync.Mutex
	cachedQuoteDataErr error
	cachedQuoteDataT   time.Time
)

func GetQuotesForToken(e wltintf.Env, token string) (*CMCQuoteData, error) {
	dat, err := getQuotesData(e)
	if err != nil {
		return nil, err
	}
	for _, v := range dat {
		if v.Symbol == token {
			return v, nil
		}
	}
	return nil, fs.ErrNotExist
}

func getQuotesData(e wltintf.Env) ([]*CMCQuoteData, error) {
	cachedQuoteDataLk.Lock()
	defer cachedQuoteDataLk.Unlock()

	if time.Since(cachedQuoteDataT) < 5*time.Minute {
		return cachedQuoteData, cachedQuoteDataErr
	}

	buf, err := getQuotesRawDataCache(e)
	if err != nil {
		if cachedQuoteData == nil {
			cachedQuoteDataErr = err
		}
		cachedQuoteDataT = time.Now()
		return nil, err
	}

	// parse json
	var quoteData []*CMCQuoteData
	err = pjson.Unmarshal(buf, &quoteData)
	if err != nil {
		if cachedQuoteData != nil {
			return cachedQuoteData, nil
		}
		return nil, err
	}

	cachedQuoteData = quoteData
	cachedQuoteDataErr = nil
	cachedQuoteDataT = time.Now()

	return quoteData, nil
}

const quoteCacheKey = "rest:Crypto/DataCache:quotes"

func getQuotesRawDataCache(e wltintf.Env) (pjson.RawMessage, error) {
	// try loading from cache
	dat, err := e.CacheLoad(quoteCacheKey)
	if err == nil && dat != nil {
		return dat, nil
	}

	// cache miss or expired, fetch fresh data
	freshData, err := getQuotesRawData(e)
	if err != nil {
		return nil, err
	}

	// store with 5 minute TTL
	e.CacheStore(quoteCacheKey, freshData, 5*time.Minute)
	return freshData, nil
}

func getQuotesRawData(e wltintf.Env) (pjson.RawMessage, error) {
	data, err := rest.Do(context.Background(), "Crypto/DataCache:quotes", "GET", nil)
	if err != nil {
		return nil, err
	}
	return data.Data, nil
}
