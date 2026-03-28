package wltwallet

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/rest"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/xuid"
	ecdsakeygen "github.com/KarpelesLab/tss-lib/v2/ecdsa/keygen"
	eddsakeygen "github.com/KarpelesLab/tss-lib/v2/eddsa/keygen"
	"github.com/fxamacker/cbor/v2"
	"github.com/portablesql/psql"
)

type WalletKey struct {
	psql.Name `sql:"WalletKey"`
	Id        *xuid.XUID `sql:",key=PRIMARY"`
	Wallet    *xuid.XUID `sql:",type=VARCHAR,size=255"`
	Type      string     `sql:",type=VARCHAR,size=255"`
	Key       string     `json:"Key,omitempty" sql:",type=TEXT"` // (public) key used for encryption
	Data      []byte     `json:",protect" sql:",type=BLOB"`
	Gen       uint64     `sql:",type=BIGINT,null=0,default=0"` // key generation
	pre       *ecdsakeygen.LocalPreParams
	sdata     *ecdsakeygen.LocalPartySaveData
	eddata    *eddsakeygen.LocalPartySaveData
}

func (wk *WalletKey) save(e wltintf.Env) error {
	return psql.Replace(e, wk)
}

func (w *Wallet) createWalletKey(ctx context.Context, typ string) (*WalletKey, error) {
	final := &WalletKey{
		Id:     xuid.New("wkey"),
		Wallet: w.Id,
		Type:   typ,
		Gen:    w.Gen + 1, // always use base gen +1, wallet gen will be updated on save
	}
	if w.Curve == "ed25519" {
		// EdDSA does not need Paillier pre-params
		return final, nil
	}
	// ECDSA needs pre-params
	preParams, err := ecdsakeygen.GeneratePreParamsWithContext(ctx)
	if err != nil {
		return nil, err
	}
	final.pre = preParams
	return final, nil
}

// encrypt stores wk.sdata or wk.eddata into wk.Data
func (wk *WalletKey) encrypt(kd *wltsign.KeyDescription) error {
	var dataToEncrypt any
	if wk.eddata != nil {
		dataToEncrypt = wk.eddata
	} else {
		dataToEncrypt = wk.sdata
	}
	res, err := cryptutil.MarshalJson(dataToEncrypt)
	if err != nil {
		return err
	}

	wk.Type = kd.Type

	switch kd.Type {
	case "StoreKey":
		// encrypt
		pubKey, err := storeKeyReadPublic(kd.Key)
		if err != nil {
			return err
		}
		pubKeyB, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return err
		}
		wk.Key = base64.RawURLEncoding.EncodeToString(pubKeyB)
		// encrypt for our key
		err = res.Encrypt(rand.Reader, pubKey)
		if err != nil {
			return err
		}
	case "RemoteKey":
		// store on remote server
		// First, get keys of machines that will need to be able to decrypt this
		var ids []string
		err = rest.Apply(context.Background(), "EllipX/WalletSign:keys", "GET", nil, &ids)
		if err != nil {
			err = rest.Apply(context.Background(), "EllipX/WalletSign:keys", "GET", nil, &ids)
			if err != nil {
				return err
			}
		}
		var keys []crypto.PublicKey
		for _, idStr := range ids {
			idC := &cryptutil.IDCard{}
			idBin, err := base64.RawURLEncoding.DecodeString(idStr)
			if err != nil {
				return err
			}
			err = idC.UnmarshalBinary(idBin)
			if err != nil {
				return err
			}
			keys = append(keys, idC.GetKeys("decrypt")...)
		}
		// encrypt bottle
		err = res.Encrypt(rand.Reader, keys...)
		if err != nil {
			return err
		}
	case "Plain":
		// do nothing
	case "Password":
		pk, err := passwordToEd25519(kd.Key, wk.Id.UUID[:])
		if err != nil {
			return err
		}
		pubKey := pk.Public()
		pubKeyB, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return err
		}
		wk.Key = base64.RawURLEncoding.EncodeToString(pubKeyB)
		// encrypt for our key
		err = res.Encrypt(rand.Reader, pubKey)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported key type %s", kd.Type)
	}

	buf, err := cbor.Marshal(res)
	if err != nil {
		return err
	}
	if kd.Type == "RemoteKey" {
		// upload bottle
		_, err = rest.Do(context.Background(), "EllipX/WalletSign:setGeneratedKey", "POST", rest.Param{"data": base64.RawURLEncoding.EncodeToString(buf), "key": kd.Key})
		if err != nil {
			return err
		}
		wk.Key = kd.Key
	}
	wk.Data = buf
	return nil
}

func (wk *WalletKey) opener(kd *wltsign.KeyDescription) (*cryptutil.Opener, error) {
	switch wk.Type {
	case "StoreKey":
		k, err := storeKeyToEd25519(kd.Key)
		if err != nil {
			return nil, err
		}
		pkBin, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			return nil, err
		}
		curPkBin, err := base64.RawURLEncoding.DecodeString(wk.Key)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pkBin, curPkBin) {
			return nil, ErrBadStoreKey
		}
		return cryptutil.NewOpener(k)
	case "Password":
		pk, err := passwordToEd25519(kd.Key, wk.Id.UUID[:])
		if err != nil {
			return nil, err
		}
		pkBin, err := x509.MarshalPKIXPublicKey(pk.Public())
		if err != nil {
			return nil, err
		}
		curPkBin, err := base64.RawURLEncoding.DecodeString(wk.Key)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pkBin, curPkBin) {
			return nil, ErrBadPassword
		}
		return cryptutil.NewOpener(pk)
	case "Plain":
		return cryptutil.EmptyOpener, nil
	default:
		return nil, fmt.Errorf("cannot open keys of type %s", wk.Type)
	}
}

func (wk *WalletKey) decrypt(kd *wltsign.KeyDescription, purpose keyUsagePurpose) (*ecdsakeygen.LocalPartySaveData, error) {
	bottle := cryptutil.AsCborBottle(wk.Data)
	op, err := wk.opener(kd)
	if err != nil {
		return nil, err
	}
	var final *ecdsakeygen.LocalPartySaveData
	_, err = op.Unmarshal(bottle, &final)
	if err != nil {
		return nil, fmt.Errorf("while decrypting key %s: %w", wk.Id, err)
	}
	return final, err
}

func (wk *WalletKey) decryptEdDSA(kd *wltsign.KeyDescription, purpose keyUsagePurpose) (*eddsakeygen.LocalPartySaveData, error) {
	bottle := cryptutil.AsCborBottle(wk.Data)
	op, err := wk.opener(kd)
	if err != nil {
		return nil, err
	}
	var final *eddsakeygen.LocalPartySaveData
	_, err = op.Unmarshal(bottle, &final)
	if err != nil {
		return nil, fmt.Errorf("while decrypting eddsa key %s: %w", wk.Id, err)
	}
	return final, err
}

func selectPeer(ctx context.Context, spot *spotlib.Client) (string, error) {
	var ids []string
	err := rest.Apply(ctx, "EllipX/WalletSign:keys", "GET", nil, &ids)
	if err != nil {
		err = rest.Apply(ctx, "EllipX/WalletSign:keys", "GET", nil, &ids)
		if err != nil {
			return "", err
		}
	}
	var keys []string
	for _, idStr := range ids {
		idC := &cryptutil.IDCard{}
		idBin, err := base64.RawURLEncoding.DecodeString(idStr)
		if err != nil {
			return "", err
		}
		err = idC.UnmarshalBinary(idBin)
		if err != nil {
			log.Printf("failed to parse peer ID: %s", err)
			continue
		}

		key := "k." + base64.RawURLEncoding.EncodeToString(cryptutil.Hash(idC.Self, sha256.New))
		keys = append(keys, key)
	}

	// let's try to ping
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res := make(chan string, 1)

	for _, k := range keys {
		go func(k string) {
			pingBuf := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, pingBuf); err != nil {
				log.Printf("failed to read random: %s", err)
				return
			}
			x, err := spot.Query(ctx, k+"/ping", pingBuf)
			if err != nil {
				log.Printf("failed to read from %s: %s", k, err)
				return
			}
			if !bytes.Equal(pingBuf, x) {
				log.Printf("bad buffer from %s", k)
				return
			}
			select {
			case res <- k:
			default:
			}
		}(k)
	}

	select {
	case v := <-res:
		return v, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
