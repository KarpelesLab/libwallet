package wltwallet

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"golang.org/x/crypto/pbkdf2"
)

func init() {
	pobj.RegisterStatic("StoreKey:create", storekeyCreate)
	pobj.RegisterStatic("StoreKey:derivePassword", storekeyDerivePassword)
}

func storekeyCreate() (any, error) {
	dat := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, dat)
	if err != nil {
		return nil, err
	}
	defer cryptutil.MemClr(dat)
	k := base64.RawURLEncoding.EncodeToString(dat)

	pk, err := storeKeyToEd25519(k)
	if err != nil {
		return nil, err
	}
	defer cryptutil.MemClr(pk)
	pub := pk.Public()
	pubBin, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	res := map[string]any{
		"private": k,
		"public":  base64.RawURLEncoding.EncodeToString(pubBin),
	}

	return res, nil
}

func storeKeyToEd25519(storeKey string) (ed25519.PrivateKey, error) {
	k, err := base64.RawURLEncoding.DecodeString(storeKey)
	if err != nil {
		return nil, err
	}
	defer cryptutil.MemClr(k)

	if len(k) != 64 {
		return nil, errors.New("invalid storeKey format (must be 64 bytes long)")
	}

	k2 := pbkdf2.Key(k[:32], k[32:], 4096, ed25519.SeedSize, sha256.New)
	defer cryptutil.MemClr(k2)

	return ed25519.NewKeyFromSeed(k2), nil
}

func passwordToEd25519(pwd string, salt []byte) (ed25519.PrivateKey, error) {
	if len(pwd) < 6 {
		return nil, fmt.Errorf("password is too short")
	}
	k := pbkdf2.Key([]byte(pwd), salt, 4096, ed25519.SeedSize, sha256.New)
	defer cryptutil.MemClr(k)

	return ed25519.NewKeyFromSeed(k), nil
}

func storeKeyReadPublic(public string) (crypto.PublicKey, error) {
	k, err := base64.RawURLEncoding.DecodeString(public)
	if err != nil {
		return nil, err
	}
	if len(k) == 64 {
		// this is a private key very likely! (public key is ~44 bytes)
		defer cryptutil.MemClr(k)
		return nil, errors.New("the received storeKey looks like a private key, was expecting a public key")
	}
	return x509.ParsePKIXPublicKey(k)
}

func storekeyDerivePassword(ctx context.Context, in struct {
	Password    string
	WalletKeyId string
}) (any, error) {
	id, err := xuid.Parse(in.WalletKeyId)
	if err != nil {
		return nil, err
	}
	if id.Prefix != "wkey" {
		return nil, errors.New("bad prefix, expected wkey")
	}

	pk, err := passwordToEd25519(in.Password, id.UUID[:])
	if err != nil {
		return nil, err
	}
	defer cryptutil.MemClr(pk)

	pub, err := x509.MarshalPKIXPublicKey(pk.Public())
	if err != nil {
		return nil, err
	}

	return map[string]any{"Public_Key": base64.RawURLEncoding.EncodeToString(pub)}, nil
}
