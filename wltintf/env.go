package wltintf

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/emitter"
	"github.com/KarpelesLab/spotlib"
	"github.com/portablesql/psql"
)

type Env interface {
	context.Context // psql backend is plugged into this context

	SetCurrent(k, v string) error
	GetCurrent(k string) (string, error)
	Emitter() *emitter.Hub
	Spot() *spotlib.Client
	CacheGet(ctx context.Context, u string, timeout, refresh time.Duration) ([]byte, error)

	// config key-value store
	ConfigGet(key string) ([]byte, error)
	ConfigSet(key string, value []byte) error

	// cache with expiration
	CacheStore(key string, value []byte, ttl time.Duration) error
	CacheLoad(key string) ([]byte, error)
	CacheDelete(keys ...string) error
}

func GetEnv(ctx context.Context) Env {
	var c *apirouter.Context
	ctx.Value(&c)
	if c == nil {
		return nil
	}
	v, ok := c.GetObject("@env").(Env)
	if ok {
		return v
	}
	return nil
}

func ByPrimaryKey[T any](e Env, id any) (*T, error) {
	return psql.Get[T](e, map[string]any{"Id": id})
}

func ListHelper[T any](ctx context.Context, sort string, searchKey ...string) (any, error) {
	e := GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	var opts []*psql.FetchOptions
	if sort != "" {
		// parse "Field ASC" or "Field DESC"
		parts := strings.SplitN(sort, " ", 2)
		dir := "ASC"
		if len(parts) == 2 {
			dir = parts[1]
		}
		opts = append(opts, psql.Sort(psql.S(parts[0], dir)))
	}
	return psql.Fetch[T](e, nil, opts...)
}
