package wltwc

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestType0RoundTrip(t *testing.T) {
	key := make([]byte, symKeySize)
	rand.Read(key)
	plain := []byte(`{"id":1,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{}}`)

	env, err := sealType0(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, sender, err := openEnvelope(key, nil, []byte(env))
	if err != nil {
		t.Fatal(err)
	}
	if sender != nil {
		t.Error("type-0 should not yield a sender pubkey")
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("plaintext mismatch: got %q want %q", got, plain)
	}
}

func TestType1RoundTrip(t *testing.T) {
	// The recipient (wallet) holds a long-lived keypair used for the
	// proposal envelope only.
	recvPriv, recvPub, err := newX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`wc_sessionPropose payload`)

	env, senderPub, _, err := sealType1(recvPub, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, gotSender, err := openEnvelope(nil, recvPriv, []byte(env))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("plaintext mismatch: got %q want %q", got, plain)
	}
	if !bytes.Equal(gotSender, senderPub) {
		t.Errorf("sender pubkey mismatch: got %x want %x", gotSender, senderPub)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	key1 := make([]byte, symKeySize)
	key2 := make([]byte, symKeySize)
	rand.Read(key1)
	rand.Read(key2)
	env, err := sealType0(key1, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := openEnvelope(key2, nil, []byte(env)); err == nil {
		t.Error("expected decryption with wrong key to fail")
	}
}

func TestTopicFromSymKeyHexLength(t *testing.T) {
	key := make([]byte, symKeySize)
	rand.Read(key)
	topic := topicFromSymKey(key)
	if len(topic) != 64 {
		t.Errorf("expected 64-char hex topic, got %d", len(topic))
	}
	if _, err := hex.DecodeString(topic); err != nil {
		t.Errorf("topic is not valid hex: %v", err)
	}
}

func TestDeriveSymKeyMatchesBothSides(t *testing.T) {
	aPriv, aPub, err := newX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bPriv, bPub, err := newX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	aKey, err := deriveSymKey(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	bKey, err := deriveSymKey(bPriv, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aKey, bKey) {
		t.Errorf("derived keys differ: a=%x b=%x", aKey, bKey)
	}
}
