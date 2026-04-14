package wltwc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestParsePairingURI(t *testing.T) {
	key := make([]byte, symKeySize)
	rand.Read(key)
	topic := topicFromSymKey(key)
	uri := fmt.Sprintf("wc:%s@2?relay-protocol=irn&symKey=%s", topic, hex.EncodeToString(key))

	p, err := parsePairingURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.Topic != topic {
		t.Errorf("topic mismatch: %s vs %s", p.Topic, topic)
	}
	if p.Version != "2" {
		t.Errorf("version = %q", p.Version)
	}
	if p.Protocol != "irn" {
		t.Errorf("protocol = %q", p.Protocol)
	}
	if len(p.SymKey) != symKeySize {
		t.Errorf("symKey len = %d", len(p.SymKey))
	}
}

func TestParsePairingURIRejectsBadTopic(t *testing.T) {
	key := make([]byte, symKeySize)
	rand.Read(key)
	// Topic doesn't match sha256(symKey)
	bad := fmt.Sprintf("wc:%064x@2?symKey=%s", 0xdeadbeef, hex.EncodeToString(key))
	if _, err := parsePairingURI(bad); err == nil {
		t.Error("expected topic-mismatch error")
	}
}

func TestParsePairingURIRejectsV1(t *testing.T) {
	if _, err := parsePairingURI("wc:abc@1?bridge=https://example.com"); err == nil {
		t.Error("expected unsupported version error")
	}
}

func TestParsePairingURIRejectsBadSymKey(t *testing.T) {
	if _, err := parsePairingURI("wc:aaaa@2?symKey=notHex"); err == nil {
		t.Error("expected symKey-decode error")
	}
	shortKey := hex.EncodeToString(make([]byte, 16))
	if _, err := parsePairingURI("wc:aaaa@2?symKey=" + shortKey); err == nil {
		t.Error("expected symKey-length error")
	}
}
