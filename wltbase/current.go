package wltbase

import (
	"io/fs"
	"os"
	"time"

	"github.com/portablesql/psql"
)

type currentItem struct {
	psql.Name `sql:"CurrentItem"`
	Key       string    `sql:",key=PRIMARY,type=VARCHAR,size=255"`
	Value     string    `sql:",type=TEXT"`
	Created   time.Time `sql:",type=DATETIME"`
	Updated   time.Time `sql:",type=DATETIME"`
}

func (ci *currentItem) BeforeSave(ctx interface{}) error {
	now := time.Now()
	if ci.Created.IsZero() {
		ci.Created = now
	}
	ci.Updated = now
	return nil
}

func (e *env) SetCurrent(k, v string) error {
	return psql.Replace(e.sqlCtx, &currentItem{Key: k, Value: v})
}

func (e *env) GetCurrent(k string) (string, error) {
	ci, err := psql.Get[currentItem](e.sqlCtx, map[string]any{"Key": k})
	if err != nil {
		if os.IsNotExist(err) {
			return "", fs.ErrNotExist
		}
		return "", err
	}
	return ci.Value, nil
}
