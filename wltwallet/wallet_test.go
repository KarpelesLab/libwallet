package wltwallet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"testing"

	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/ModChain/secp256k1"
)

// testPhone is a known invalid phone number but just valid enough so it can be input in a phone number input field
const testPhone = "+14045551234" // code=000000

func TestWalletCreate(t *testing.T) {
	w := &Wallet{}

	log.Printf("storeKey = %+v", must(storekeyCreate()))

	remoteKey := must(remoteNew(context.Background(), testPhone))
	verify := must(remoteVerify(context.Background(), remoteKey.Session, "000000"))
	log.Printf("made session = %+v", verify)

	kd := []*wltsign.KeyDescription{
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{Type: "Plain"},
	}

	err := w.initializeWallet(context.Background(), kd)
	if err != nil {
		t.Errorf("failed to init: %s", err)
		return
	}

	log.Printf("wallet ready")

	// test sig
	opts := &wltsign.Opts{}

	for _, k := range w.Keys[:2] {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}

	s := []byte("hello world")
	sHash := sha256.Sum256(s)

	sig, err := w.Sign(rand.Reader, sHash[:], opts)
	if err != nil {
		t.Errorf("failed to sign: %s", err)
		return
	}

	log.Printf("signature data (len %d) = %x", len(sig), sig)

	sigO, err := secp256k1.ParseDERSignature(sig)
	if err != nil {
		t.Errorf("failed to parse sign: %s", err)
		return
	}

	// extract public key
	pubk := must(secp256k1.ParsePubKey(must(base64.RawURLEncoding.DecodeString(w.Pubkey))))

	sigO.BruteforceRecoveryCode(sHash[:], pubk)

	// transform signature into ethereum format
	sigC := sigO.ExportCompact(true, 27)

	// check if signature is valid
	//log.Printf("wallet pubkey = %v", pubk)
	pk, compressed, err := secp256k1.RecoverCompact(sigC, sHash[:])

	if err != nil {
		t.Errorf("failed to recover ECDSA key from signature: %s", err)
	} else if compressed {
		t.Errorf("invalid compressed flag, expected compressed=false")
	} else if !pk.IsEqual(pubk) {
		t.Errorf("invalid signature (public key did not match")
	}
	// all good

	// let's try reshare
	newKd := []*wltsign.KeyDescription{
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{Type: "Plain"},
		&wltsign.KeyDescription{Type: "Plain"},
	}

	err = w.Reshare(context.Background(), opts.Keys, newKd)
	if err != nil {
		t.Errorf("failed to reshare wallet: %s", err)
		return
	}

	// let's try to sign again after reshare

	// first, fetch the new keys
	opts = &wltsign.Opts{}
	for _, k := range w.Keys[:2] {
		opts.Keys = append(opts.Keys, &wltsign.KeyDescription{Id: k.Id.String()})
	}

	s = []byte("hello world2")
	sHash = sha256.Sum256(s)

	sig, err = w.Sign(rand.Reader, sHash[:], opts)
	if err != nil {
		t.Errorf("failed to sign: %s", err)
		return
	}

	log.Printf("signature data (len %d) = %x", len(sig), sig)

	sigO, err = secp256k1.ParseDERSignature(sig)
	if err != nil {
		t.Errorf("failed to parse sign: %s", err)
		return
	}

	// extract public key
	pubk = must(secp256k1.ParsePubKey(must(base64.RawURLEncoding.DecodeString(w.Pubkey))))

	sigO.BruteforceRecoveryCode(sHash[:], pubk)

	// transform signature into ethereum format
	sigC = sigO.ExportCompact(true, 27)

	// check if signature is valid
	//log.Printf("wallet pubkey = %v", pubk)
	pk, compressed, err = secp256k1.RecoverCompact(sigC, sHash[:])

	if err != nil {
		t.Errorf("failed to recover ECDSA key from signature: %s", err)
	} else if compressed {
		t.Errorf("invalid compressed flag, expected compressed=false")
	} else if !pk.IsEqual(pubk) {
		t.Errorf("invalid signature (public key did not match")
	}
	// all good
}

func must[T any](a T, err error) T {
	if err != nil {
		panic(err)
	}
	return a
}
