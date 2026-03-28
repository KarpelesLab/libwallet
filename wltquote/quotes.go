package wltquote

import (
	"context"
	"encoding/binary"
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

func getQuotesRawDataCache(e wltintf.Env) (pjson.RawMessage, error) {
	// grab from cache
	dat, err := e.DBSimpleGet([]byte("rest_cache"), []byte("Crypto/DataCache:quotes"))
	if err != nil {
		dat, err = getQuotesRawData(e)
		if err != nil {
			return nil, err
		}
		ts := make([]byte, 8)
		binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
		dat = append(ts, dat...)
		e.DBSimpleSet([]byte("rest_cache"), []byte("Crypto/DataCache:quotes"), dat)
	}

	cacheTime := time.Unix(int64(binary.BigEndian.Uint64(dat[:8])), 0)
	if time.Since(cacheTime) <= 5*time.Minute {
		return dat[8:], nil
	}

	// attempt to refresh cache
	newdat, err := getQuotesRawData(e)
	if err != nil {
		// failed, return old stale data
		return dat[8:], nil
	}
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	dat = append(ts, newdat...)
	e.DBSimpleSet([]byte("rest_cache"), []byte("Crypto/DataCache:quotes"), dat)

	return dat[8:], nil
}

func getQuotesRawData(e wltintf.Env) (pjson.RawMessage, error) {
	data, err := rest.Do(context.Background(), "Crypto/DataCache:quotes", "GET", nil)
	if err != nil {
		return nil, err
	}
	return data.Data, nil
}
