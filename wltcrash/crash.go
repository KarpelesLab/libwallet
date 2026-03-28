package wltcrash

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
	"github.com/google/uuid"
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
	Id      uuid.UUID `gorm:"primaryKey;type:uuid"`
	Where   string
	Message string
	Stack   string
	Created time.Time `gorm:"autoCreateTime"`
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
	env.Save(crash)

	return id
}

func InitEnv(env wltintf.Env) {
	// Create the crash table
	env.AutoMigrate(&Crash{})
}

func apiFetchCrash(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	var crash Crash
	err := e.FirstId(&crash, in.Id)
	if err != nil {
		return nil, err
	}

	return &crash, nil
}

func apiListCrash(ctx *apirouter.Context) (any, error) {
	return wltintf.ListHelper[Crash](ctx, "Created ASC", "Crash")
}

func (crash *Crash) ApiDelete(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	return e.Delete(crash)
}
