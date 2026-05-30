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

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/rest"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/tss-lib/v2/dklstss"
	"github.com/KarpelesLab/tss-lib/v2/ecdsatss"
	"github.com/KarpelesLab/tss-lib/v2/eddsatss"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/xuid"
	"github.com/fxamacker/cbor/v2"
	"github.com/portablesql/psql"
)

// WalletKey represents one share of a wallet's signing key.
//
// Two orthogonal axes:
//
//   - Type   — how the encrypted blob is wrapped (StoreKey / Plain /
//     RemoteKey / Password). This is the "encryption mechanism".
//   - Schema — what's INSIDE the encrypted blob. Empty (default for
//     existing rows) means a legacy tss-lib share picked by parent
//     Wallet.Protocol/Curve — `*ecdsatss.Key` for gg18 secp256k1
//     wallets, `*eddsatss.Key` for eddsa ed25519 wallets. Non-empty
//     schemas are:
//       - "raw"      — `*RawKeyShare`, a 32-byte private key + chaincode.
//       - "mnemonic" — `*MnemonicKeyShare`, a BIP39 mnemonic phrase.
//       - "dkls23"   — `*dklstss.Key` for modern DKLs23 secp256k1
//         wallets. Save/Load produces a binary blob (includes OT-
//         extension state) which is wrapped in [dklsKeyWrapper] so it
//         flows through the same JSON/CBOR/Bottle pipeline as the
//         other share types.
//       - "frost"    — `*frosttss.Key` for modern FROST ed25519
//         wallets (RFC 9591). Key is plain JSON-serializable, so it
//         round-trips through the encrypt/decrypt pipeline without a
//         wrapper.
//     Wallets with a "raw" or "mnemonic" Schema are 1-of-1 imports
//     (signable immediately, promotable via Wallet:promote).
type WalletKey struct {
	psql.Name `sql:"WalletKey"`
	Id        *xuid.XUID `sql:",key=PRIMARY"`
	Wallet    *xuid.XUID `sql:",type=VARCHAR,size=255"`
	Type      string     `sql:",type=VARCHAR,size=255"`
	Schema    string     `sql:",type=VARCHAR,size=64,null=0,default=''"` // "" | "raw" | "mnemonic" | "dkls23" | "frost"
	Key       string     `json:"Key,omitempty" sql:",type=TEXT"`         // (public) key used for encryption
	Data      []byte     `json:",protect" sql:",type=BLOB"`
	Gen       uint64     `sql:",type=BIGINT,null=0,default=0"` // key generation
	pre       *ecdsatss.LocalPreParams
	sdata     *ecdsatss.Key
	eddata    *eddsatss.Key
	dklsData  *dklstss.Key      // populated when Schema == "dkls23"
	frostData *frosttss.Key     // populated when Schema == "frost"
	rawData   *RawKeyShare      // populated when Schema == "raw"
	mnemonic  *MnemonicKeyShare // populated when Schema == "mnemonic"
}

// dklsKeyWrapper is the wire form for a dklstss share inside the
// encrypted Bottle. dklstss.Key.Save() emits a binary blob (includes
// OT-extension setup state) rather than json-marshalling itself, so we
// box the bytes in a struct that does round-trip through JSON cleanly.
type dklsKeyWrapper struct {
	Data []byte `json:"data"`
}

// RawKeyShare is the decrypted payload for a WalletKey with
// Schema == "raw" — a single private key (hex / WIF import).
type RawKeyShare struct {
	Curve     string `json:"curve"`     // "secp256k1" | "ed25519"
	Privkey   []byte `json:"privkey"`   // 32 bytes
	Chaincode []byte `json:"chaincode"` // 32 bytes; random for hex/WIF imports, empty allowed
}

// MnemonicKeyShare is the decrypted payload for a WalletKey with
// Schema == "mnemonic" — a BIP39 mnemonic stored as its decoded
// entropy + the language wordlist it was imported in. The mnemonic
// itself can be reconstructed (and re-rendered in any other BIP39
// language by re-encoding the entropy against that language's
// wordlist) for backup display.
//
// Why entropy + language instead of the raw mnemonic string:
//   - Display: we can show the same backup in English / Japanese /
//     French / etc. by re-encoding entropy. The user's preference
//     is purely a UX choice.
//   - Sign: BIP39 PBKDF2(mnemonic_string, "mnemonic"+passphrase)
//     IS sensitive to which language's wordlist was used at import,
//     so we always reconstruct using the stored Language to keep
//     the derived seed (and therefore the wallet's address) stable.
//
// The privkey is re-derived on every sign (cacheable per session via
// the caller), so the mnemonic remains the source of truth and the
// wallet supports arbitrary BIP44 / SLIP-0010 derivation paths
// including hardened components — matching MetaMask / Phantom
// semantics.
type MnemonicKeyShare struct {
	Curve      string `json:"curve"`      // "secp256k1" | "ed25519"
	Entropy    []byte `json:"entropy"`    // 16/20/24/28/32 bytes = 128/160/192/224/256 bits
	Language   string `json:"language"`   // BIP39 wordlist used at import: "english" | "japanese" | ...
	Passphrase string `json:"passphrase"` // optional BIP39 passphrase ("" when absent)
}

func (wk *WalletKey) save(e wltintf.Env) error {
	return psql.Replace(e, wk)
}

// createWalletKey generates a single wallet key share. For ECDSA wallets this
// includes slow Paillier + NTilde safe-prime generation; scope receives fine-
// grained progress (one tick per accepted safe prime out of 4). EdDSA keys
// are effectively instant and just mark the scope complete.
func (w *Wallet) createWalletKey(ctx context.Context, typ string, scope progressScope) (*WalletKey, error) {
	final := &WalletKey{
		Id:     xuid.New("wkey"),
		Wallet: w.Id,
		Type:   typ,
		Gen:    w.Gen + 1, // always use base gen +1, wallet gen will be updated on save
	}
	if w.Curve == "ed25519" {
		scope.report(1)
		return final, nil
	}
	gen := &ecdsatss.LocalPreGenerator{
		Context: ctx,
		Progress: func(p ecdsatss.PreParamsProgress) {
			if p.SafePrimesTotal > 0 {
				scope.report(float64(p.SafePrimesFound) / float64(p.SafePrimesTotal))
			}
		},
	}
	preParams, err := gen.Generate()
	if err != nil {
		return nil, err
	}
	final.pre = preParams
	scope.report(1)
	return final, nil
}

// encrypt stores the active in-memory share (sdata/eddata/dklsData/
// frostData/rawData/mnemonic) into wk.Data, encrypted per the given
// KeyDescription. Schema is set based on which field is populated so
// decrypt knows what type to unmarshal back into.
func (wk *WalletKey) encrypt(kd *wltsign.KeyDescription) error {
	var dataToEncrypt any
	switch {
	case wk.mnemonic != nil:
		dataToEncrypt = wk.mnemonic
		wk.Schema = "mnemonic"
	case wk.rawData != nil:
		dataToEncrypt = wk.rawData
		wk.Schema = "raw"
	case wk.dklsData != nil:
		// dklstss.Key.Save() is binary; wrap in dklsKeyWrapper so the
		// rest of the encrypt pipeline (Bottle / cryptutil / CBOR)
		// doesn't have to learn about a non-JSON share type.
		var buf bytes.Buffer
		if err := wk.dklsData.Save(&buf); err != nil {
			return fmt.Errorf("dklstss.Key.Save: %w", err)
		}
		dataToEncrypt = &dklsKeyWrapper{Data: buf.Bytes()}
		wk.Schema = "dkls23"
	case wk.frostData != nil:
		dataToEncrypt = wk.frostData
		wk.Schema = "frost"
	case wk.eddata != nil:
		dataToEncrypt = wk.eddata
		wk.Schema = ""
	default:
		dataToEncrypt = wk.sdata
		wk.Schema = ""
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
		err = restApplyRetry(withClientID(context.Background()), "Crypto/WalletSign:keys", "GET", nil, &ids)
		if err != nil {
			err = restApplyRetry(withClientID(context.Background()), "Crypto/WalletSign:keys", "GET", nil, &ids)
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
		// upload bottle. curveParam tells the WalletSign backend which
		// elliptic curve the share is for — secp256k1 for both legacy
		// ecdsatss and modern dkls23, ed25519 for both eddsatss and
		// (future) frost. The protocol distinction is encoded inside
		// the encrypted blob's Schema, not on the upload side.
		curveParam := "secp256k1"
		if wk.eddata != nil || wk.frostData != nil {
			curveParam = "ed25519"
		}
		_, err = restDoRetry(withClientID(context.Background()), "Crypto/WalletSign:setGeneratedKey", "POST", rest.Param{"data": base64.RawURLEncoding.EncodeToString(buf), "key": kd.Key, "curve": curveParam})
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

func (wk *WalletKey) decrypt(kd *wltsign.KeyDescription, purpose keyUsagePurpose) (*ecdsatss.Key, error) {
	bottle := cryptutil.AsCborBottle(wk.Data)
	op, err := wk.opener(kd)
	if err != nil {
		return nil, err
	}
	var final *ecdsatss.Key
	_, err = op.Unmarshal(bottle, &final)
	if err != nil {
		return nil, fmt.Errorf("while decrypting key %s: %w", wk.Id, err)
	}
	return final, err
}

// decryptDkls unwraps a Schema=="dkls23" WalletKey into the
// dklstss.Key share. Errors if the WalletKey wasn't generated by the
// dklstss path (different Schema, no Save bytes in the bottle, etc.).
func (wk *WalletKey) decryptDkls(kd *wltsign.KeyDescription, purpose keyUsagePurpose) (*dklstss.Key, error) {
	if wk.Schema != "dkls23" {
		return nil, fmt.Errorf("walletkey %s is not a dkls23 share (schema=%q)", wk.Id, wk.Schema)
	}
	bottle := cryptutil.AsCborBottle(wk.Data)
	op, err := wk.opener(kd)
	if err != nil {
		return nil, err
	}
	var wrapper *dklsKeyWrapper
	if _, err := op.Unmarshal(bottle, &wrapper); err != nil {
		return nil, fmt.Errorf("while decrypting dkls23 key %s: %w", wk.Id, err)
	}
	if wrapper == nil || len(wrapper.Data) == 0 {
		return nil, fmt.Errorf("dkls23 key %s: empty Save bytes after decrypt", wk.Id)
	}
	key, err := dklstss.Load(bytes.NewReader(wrapper.Data))
	if err != nil {
		return nil, fmt.Errorf("dklstss.Load on key %s: %w", wk.Id, err)
	}
	return key, nil
}

// decryptFrost unwraps a Schema=="frost" WalletKey into the FROST share.
// Errors if the WalletKey isn't a FROST share.
func (wk *WalletKey) decryptFrost(kd *wltsign.KeyDescription, purpose keyUsagePurpose) (*frosttss.Key, error) {
	if wk.Schema != "frost" {
		return nil, fmt.Errorf("walletkey %s is not a frost share (schema=%q)", wk.Id, wk.Schema)
	}
	bottle := cryptutil.AsCborBottle(wk.Data)
	op, err := wk.opener(kd)
	if err != nil {
		return nil, err
	}
	var final *frosttss.Key
	if _, err = op.Unmarshal(bottle, &final); err != nil {
		return nil, fmt.Errorf("while decrypting frost key %s: %w", wk.Id, err)
	}
	return final, nil
}

func (wk *WalletKey) decryptEdDSA(kd *wltsign.KeyDescription, purpose keyUsagePurpose) (*eddsatss.Key, error) {
	bottle := cryptutil.AsCborBottle(wk.Data)
	op, err := wk.opener(kd)
	if err != nil {
		return nil, err
	}
	var final *eddsatss.Key
	_, err = op.Unmarshal(bottle, &final)
	if err != nil {
		return nil, fmt.Errorf("while decrypting eddsa key %s: %w", wk.Id, err)
	}
	// Fail loudly on a malformed share instead of letting callers
	// segfault inside (*ECPoint).ToEd25519PubKey on a nil receiver.
	// Hits when a non-eddsa share (e.g. a FROST payload routed through
	// the wrong helper) gets CBOR-decoded into *eddsatss.Key — fxamacker
	// silently zero-fills unknown fields, so the unmarshal returns nil.
	if final == nil || final.EDDSAPub == nil {
		return nil, fmt.Errorf("eddsa key %s decoded without EDDSAPub (wrong share schema for this helper?)", wk.Id)
	}
	return final, nil
}

// decryptRaw unwraps a Schema=="raw" WalletKey into the imported
// RawKeyShare. Errors if the WalletKey isn't a raw import.
func (wk *WalletKey) decryptRaw(kd *wltsign.KeyDescription) (*RawKeyShare, error) {
	if wk.Schema != "raw" {
		return nil, fmt.Errorf("walletkey %s is not a raw-key import (schema=%q)", wk.Id, wk.Schema)
	}
	bottle := cryptutil.AsCborBottle(wk.Data)
	op, err := wk.opener(kd)
	if err != nil {
		return nil, err
	}
	var final *RawKeyShare
	if _, err = op.Unmarshal(bottle, &final); err != nil {
		return nil, fmt.Errorf("while decrypting raw key %s: %w", wk.Id, err)
	}
	return final, nil
}

// decryptMnemonic unwraps a Schema=="mnemonic" WalletKey into the
// imported MnemonicKeyShare. Errors if the WalletKey isn't a mnemonic
// import.
func (wk *WalletKey) decryptMnemonic(kd *wltsign.KeyDescription) (*MnemonicKeyShare, error) {
	if wk.Schema != "mnemonic" {
		return nil, fmt.Errorf("walletkey %s is not a mnemonic import (schema=%q)", wk.Id, wk.Schema)
	}
	bottle := cryptutil.AsCborBottle(wk.Data)
	op, err := wk.opener(kd)
	if err != nil {
		return nil, err
	}
	var final *MnemonicKeyShare
	if _, err = op.Unmarshal(bottle, &final); err != nil {
		return nil, fmt.Errorf("while decrypting mnemonic key %s: %w", wk.Id, err)
	}
	return final, nil
}

func selectPeer(ctx context.Context, spot *spotlib.Client) (string, error) {
	ctx = withClientID(ctx)
	var ids []string
	err := restApplyRetry(ctx, "Crypto/WalletSign:keys", "GET", nil, &ids)
	if err != nil {
		err = restApplyRetry(ctx, "Crypto/WalletSign:keys", "GET", nil, &ids)
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
