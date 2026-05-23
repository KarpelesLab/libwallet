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
	// Build the WHERE clause from request params named in searchKey.
	// Until this loop was added, every caller's searchKey was silently
	// dropped — e.g. `Account?Wallet=<id>` returned every account on
	// the device regardless of which wallet was asked for (reported
	// by the tibaneapp wallet-detail screen).
	//
	// We read through the *apirouter.Context directly rather than
	// `apirouter.GetParam[any]` because the typed wrapper panics when
	// the requested param is absent and T is the bare `any` (a
	// reflect.Zero on an interface type round-trips as an untyped nil
	// that fails the final type assertion).
	var arc *apirouter.Context
	ctx.Value(&arc)
	var where map[string]any
	if arc != nil {
		for _, k := range searchKey {
			v := arc.GetParam(k)
			if v == nil {
				continue
			}
			if s, isStr := v.(string); isStr && s == "" {
				continue
			}
			if where == nil {
				where = make(map[string]any)
			}
			where[k] = v
		}
	}
	return psql.Fetch[T](e, where, opts...)
}
