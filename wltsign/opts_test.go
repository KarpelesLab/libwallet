package wltsign

import (
	"context"
	"crypto"
	"math/big"
	"testing"
)

func TestOptsHashFunc(t *testing.T) {
	opts := &Opts{}
	if h := opts.HashFunc(); h != crypto.Hash(0) {
		t.Errorf("expected crypto.Hash(0), got %v", h)
	}
}

func TestOptsFields(t *testing.T) {
	ctx := context.Background()
	il := big.NewInt(42)
	keys := []*KeyDescription{
		{Type: "StoreKey", Key: "key1", Id: "id1"},
		{Type: "RemoteKey", Key: "key2", Id: "id2"},
		{Type: "Plain", Key: "", Id: "id3"},
		{Type: "Password", Key: "pw", Id: "id4"},
	}

	opts := &Opts{
		Context: ctx,
		IL:      il,
		Keys:    keys,
	}

	if opts.Context != ctx {
		t.Error("context mismatch")
	}
	if opts.IL.Cmp(il) != 0 {
		t.Error("IL mismatch")
	}
	if len(opts.Keys) != 4 {
		t.Errorf("expected 4 keys, got %d", len(opts.Keys))
	}
	if opts.Keys[0].Type != "StoreKey" {
		t.Errorf("expected StoreKey, got %s", opts.Keys[0].Type)
	}
}

func TestKeyDescription(t *testing.T) {
	kd := &KeyDescription{
		Type: "StoreKey",
		Key:  "mykey",
		Id:   "myid",
	}
	if kd.Type != "StoreKey" {
		t.Errorf("expected StoreKey, got %s", kd.Type)
	}
	if kd.Key != "mykey" {
		t.Errorf("expected mykey, got %s", kd.Key)
	}
	if kd.Id != "myid" {
		t.Errorf("expected myid, got %s", kd.Id)
	}
}
