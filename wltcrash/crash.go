package wltcrash

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pobj"
	"github.com/google/uuid"
	"github.com/portablesql/psql"
)

func init() {
	pobj.RegisterActions[Crash]("Crash",
		&pobj.ObjectActions{
			Fetch: pobj.Static(apiFetchCrash),
			List:  pobj.Static(apiListCrash),
		},
	)
}

// Crash represents a crash event in the database
type Crash struct {
	psql.Name `sql:"Crash"`
	Id        uuid.UUID `sql:",key=PRIMARY,type=CHAR,size=36"`
	Where     string    `sql:",type=TEXT"`
	Message   string    `sql:",type=TEXT"`
	Stack     string    `sql:",type=TEXT"`
	Created   time.Time `sql:",type=DATETIME"`
}

// Log is called within a catch of a panic
func Log(ctx context.Context, e any, where string) uuid.UUID {
	id, _ := uuid.NewRandom()

	if e == nil {
		return id
	}

	env := wltintf.GetEnv(ctx)
	if env == nil {
		return id
	}

	msg := fmt.Sprintf("PANIC in %s:\n%v", where, e)
	stack := string(debug.Stack())

	// Store in database
	crash := &Crash{
		Id:      id,
		Where:   where,
		Message: msg,
		Stack:   stack,
		Created: time.Now(),
	}
	psql.Replace(env, crash)

	return id
}

func InitEnv(env wltintf.Env) {
	// psql auto-creates tables, no migration needed
}

func apiFetchCrash(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	crash, err := psql.Get[Crash](e, map[string]any{"Id": in.Id})
	if err != nil {
		return nil, err
	}

	return crash, nil
}

func apiListCrash(ctx *apirouter.Context) (any, error) {
	return wltintf.ListHelper[Crash](ctx, "Created ASC", "Crash")
}

func (crash *Crash) ApiDelete(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	_, err := psql.ForceDelete[Crash](e, map[string]any{"Id": crash.Id})
	return err
}
