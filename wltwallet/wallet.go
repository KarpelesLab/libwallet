package wltwallet

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/KarpelesLab/libwallet/wltcrash"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/xuid"
	"github.com/ModChain/secp256k1"
	"github.com/ModChain/tss-lib/v2/common"
	"github.com/ModChain/tss-lib/v2/ecdsa/keygen"
	ecdsasigning "github.com/ModChain/tss-lib/v2/ecdsa/signing"
	eddsakeygen "github.com/ModChain/tss-lib/v2/eddsa/keygen"
	eddsasigning "github.com/ModChain/tss-lib/v2/eddsa/signing"
	"github.com/ModChain/tss-lib/v2/tss"
)

// Wallet represents a multi-signature wallet with threshold signature scheme (TSS) support
// It can contain multiple keys with a configurable threshold for signatures
type Wallet struct {
	Id        *xuid.XUID   `gorm:"primaryKey"` // Unique identifier for the wallet
	Name      string       // User-friendly name
	Curve     string       // Elliptic curve used (e.g., "secp256k1")
	Threshold int          // Minimum number of keys required for signing
	Keys      []*WalletKey `gorm:"-:all"`              // Associated keys (not stored in database)
	Gen       uint64       `gorm:"not null;default:0"` // incremented on reshare
	Pubkey    string       // Base64 encoded public key
	Chaincode string       // Base64 encoded chaincode for HD wallet derivation
	Created   time.Time    `gorm:"autoCreateTime"` // Creation timestamp
	Modified  time.Time    `gorm:"autoUpdateTime"` // Last modification timestamp
}

// save persists the wallet and all its keys to the database
// Returns error with context if the save operation fails
func (w *Wallet) save(e wltintf.Env) error {
	if len(w.Keys) == 0 {
		return errors.New("wallet: cannot save a wallet with no keys")
	}
	gen := w.Keys[0].Gen

	for i, wk := range w.Keys {
		if wk.Gen != gen {
			return fmt.Errorf("wallet: inconsistent walley key generation: key[0].gen=%d but key[%d].gen=%d", gen, i, wk.Gen)
		}
	}

	// update w.Gen to make sure we load those keys in the future
	w.Gen = gen

	for i, wk := range w.Keys {
		if err := wk.save(e); err != nil {
			return fmt.Errorf("failed to save wallet key %d: %w", i, err)
		}
	}
	if err := e.Save(w); err != nil {
		return fmt.Errorf("failed to save wallet %s: %w", w.Id, err)
	}
	return nil
}

// ApiUpdate handles API requests to update wallet properties
// Currently supports updating the wallet name
// Returns nil if no updates were made or error with context if the save fails
func (w *Wallet) ApiUpdate(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return fmt.Errorf("failed to get environment from context for wallet %s", w.Id)
	}

	updated := false

	if v, ok := apirouter.GetParam[string](ctx, "Name"); ok {
		w.Name = v
		updated = true
	}
	if !updated {
		return nil
	}
	w.Modified = time.Now()
	if err := w.save(e); err != nil {
		return fmt.Errorf("failed to save wallet updates: %w", err)
	}
	return nil
}

// ApiDelete handles API requests to delete a wallet
// Emits a "wallet:deleted" event and removes the wallet and its keys from the database
// Returns error with context if the deletion fails
func (w *Wallet) ApiDelete(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return fmt.Errorf("failed to get environment from context for wallet %s", w.Id)
	}

	e.Emitter().Emit(ctx, "wallet:deleted", w.Id.String())

	// delete Wallet/Key entries
	if err := e.DeleteWhere(&WalletKey{}, map[string]any{"Wallet": w.Id.String()}); err != nil {
		return fmt.Errorf("failed to delete wallet keys for wallet %s: %w", w.Id, err)
	}

	if err := e.Delete(w); err != nil {
		return fmt.Errorf("failed to delete wallet %s: %w", w.Id, err)
	}
	return nil
}

// initializeWallet creates a new wallet with the specified key descriptions
// Implements Threshold Signature Scheme (TSS) for distributed key generation
// Parameters:
//   - ctx: context for progress reporting and cancellation
//   - kDesc: array of key descriptions for wallet creation
//
// Returns any error encountered during wallet initialization
func (w *Wallet) initializeWallet(ctx context.Context, kDesc []*wltsign.KeyDescription) error {
	if w.Threshold == 0 {
		w.Threshold = 1
	}
	nk := len(kDesc)
	w.Keys = make([]*WalletKey, nk)

	if nk == 0 {
		return errors.New("at least one key is required")
	}
	if w.Threshold >= nk {
		return errors.New("threshold too high")
	}
	if w.Threshold < 0 {
		return errors.New("threshold too low")
	}

	// Create wallet keys for each key description
	for i, kInfo := range kDesc {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
			// OK
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		log.Printf("generating key %d/%d", i, nk)
		apirouter.Progress(ctx, map[string]any{"count": nk + 1, "running": i + 1})

		k, err := w.createWalletKey(ctx, kInfo.Type)
		if err != nil {
			return fmt.Errorf("failed to create wallet key of type %s (key %d/%d): %w", kInfo.Type, i+1, nk, err)
		}
		w.Keys[i] = k
	}

	log.Printf("producing final")

	// Perform final operation (actual key generation)
	apirouter.Progress(ctx, map[string]any{"count": nk + 1, "running": nk + 1})

	// Set up TSS parties for distributed key generation
	var ids tss.UnSortedPartyIDs
	m := make(map[string]tssPartyUpdateOnly)
	idmap := make(map[int]*tss.PartyID)
	for n, p := range w.Keys {
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		ids = append(ids, id)
		idmap[n] = id
	}
	sids := tss.SortPartyIDs(ids)

	curve := tss.EC()
	tssctx := tss.NewPeerContext(sids)

	// Create channels for TSS communication
	outCh := make(chan tss.Message)
	defer close(outCh)
	var wg sync.WaitGroup
	wg.Add(len(w.Keys))

	// Start TSS key generation for each party
	for n, p := range w.Keys {
		endCh := make(chan *keygen.LocalPartySaveData)
		params := tss.NewParameters(curve, tssctx, idmap[n], nk, w.Threshold)
		party := keygen.NewLocalParty(params, outCh, endCh, *p.pre)
		m[p.Id.String()] = party
		go func(p *WalletKey) {
			defer wg.Done()
			err := party.Start()
			if err != nil {
				log.Printf("err = %s", err)
				// Ensure we don't block on channel read if party failed to start
				p.sdata = nil
				return
			}
			p.sdata = <-endCh
		}(p)
	}
	go tssRouter(ctx, m, outCh)

	// Generate random chaincode for HD wallet derivation
	chaincode := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, chaincode)
	if err != nil {
		return fmt.Errorf("failed to generate secure chaincode for wallet: %w", err)
	}

	// Wait for all key generation to complete
	wg.Wait()

	// Set wallet properties from generated keys
	pk := w.Keys[0].sdata.ECDSAPub.ToSecp256k1PubKey()
	w.Pubkey = base64.RawURLEncoding.EncodeToString(pk.SerializeCompressed())
	w.Chaincode = base64.RawURLEncoding.EncodeToString(chaincode)
	w.Curve = curve.Params().Name

	// Encrypt keys with their respective key descriptions
	for i, kInfo := range kDesc {
		err = w.Keys[i].encrypt(kInfo)
		if err != nil {
			return fmt.Errorf("failed to encrypt wallet key %d/%d of type %s: %w", i+1, len(w.Keys), kInfo.Type, err)
		}
	}

	return nil
}

// initializeEdDSAWallet creates a new Ed25519 wallet using EdDSA TSS
func (w *Wallet) initializeEdDSAWallet(ctx context.Context, kDesc []*wltsign.KeyDescription) error {
	w.Curve = "ed25519"
	if w.Threshold == 0 {
		w.Threshold = 1
	}
	nk := len(kDesc)
	w.Keys = make([]*WalletKey, nk)

	if nk == 0 {
		return errors.New("at least one key is required")
	}
	if w.Threshold >= nk {
		return errors.New("threshold too high")
	}
	if w.Threshold < 0 {
		return errors.New("threshold too low")
	}

	for i, kInfo := range kDesc {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
			// OK
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		log.Printf("generating eddsa key %d/%d", i, nk)
		apirouter.Progress(ctx, map[string]any{"count": nk + 1, "running": i + 1})

		k, err := w.createWalletKey(ctx, kInfo.Type)
		if err != nil {
			return fmt.Errorf("failed to create eddsa wallet key of type %s (key %d/%d): %w", kInfo.Type, i+1, nk, err)
		}
		w.Keys[i] = k
	}

	log.Printf("producing eddsa final")
	apirouter.Progress(ctx, map[string]any{"count": nk + 1, "running": nk + 1})

	var ids tss.UnSortedPartyIDs
	m := make(map[string]tssPartyUpdateOnly)
	idmap := make(map[int]*tss.PartyID)
	for n, p := range w.Keys {
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		ids = append(ids, id)
		idmap[n] = id
	}
	sids := tss.SortPartyIDs(ids)

	curve := tss.Edwards()
	tssctx := tss.NewPeerContext(sids)

	outCh := make(chan tss.Message)
	defer close(outCh)
	var wg sync.WaitGroup
	wg.Add(len(w.Keys))

	for n, p := range w.Keys {
		endCh := make(chan *eddsakeygen.LocalPartySaveData)
		params := tss.NewParameters(curve, tssctx, idmap[n], nk, w.Threshold)
		party := eddsakeygen.NewLocalParty(params, outCh, endCh)
		m[p.Id.String()] = party
		go func(p *WalletKey) {
			defer wg.Done()
			err := party.Start()
			if err != nil {
				log.Printf("eddsa keygen err = %s", err)
				p.eddata = nil
				return
			}
			p.eddata = <-endCh
		}(p)
	}
	go tssRouter(ctx, m, outCh)

	chaincode := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, chaincode)
	if err != nil {
		return fmt.Errorf("failed to generate secure chaincode for wallet: %w", err)
	}

	wg.Wait()

	if w.Keys[0].eddata == nil {
		return errors.New("eddsa key generation failed")
	}

	// Extract Ed25519 public key
	edPub := w.Keys[0].eddata.EDDSAPub
	pubBytes := make([]byte, 32)
	edPub.X().FillBytes(pubBytes)
	w.Pubkey = base64.RawURLEncoding.EncodeToString(pubBytes)
	w.Chaincode = base64.RawURLEncoding.EncodeToString(chaincode)

	for i, kInfo := range kDesc {
		err = w.Keys[i].encrypt(kInfo)
		if err != nil {
			return fmt.Errorf("failed to encrypt eddsa wallet key %d/%d of type %s: %w", i+1, len(w.Keys), kInfo.Type, err)
		}
	}

	return nil
}

// getKey retrieves a WalletKey by its ID string
// Returns the key if found, or nil if not found
func (w *Wallet) getKey(id string) *WalletKey {
	for _, k := range w.Keys {
		if k.Id.String() == id {
			return k
		}
	}
	return nil
}

// Sign the digest using the wallet, returning a DER encoded signature
// Implements the crypto.Signer interface
// Parameters:
//   - rand: random source (not used in TSS signatures)
//   - digest: the hash or message to sign
//   - opts: must be *wltsign.Opts containing context and key information
//
// Returns the signature and any error encountered
// Has panic recovery to prevent crashes during signature generation
func (w *Wallet) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (dat []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			// TODO might want to find a way to get the crash log
			if aopt, ok := opts.(*wltsign.Opts); ok {
				id := wltcrash.Log(aopt.Context, e, "signature main thread")
				log.Printf("panic: %s", e)
				err = fmt.Errorf("panic during signature generation, please contact support (crash id %s)", id)
			}
		}
	}()
	dat, err = w.subSign(rand, digest, opts)
	return
}

// subSign performs the actual distributed signature operation using TSS
// This is called by Sign after setting up panic recovery
// Parameters:
//   - rand: random source (not used in TSS signatures)
//   - digest: the hash or message to sign
//   - opts: must be *wltsign.Opts containing context, key information, and IL (intermediate value)
//
// Returns the DER-encoded signature and any error encountered
func (w *Wallet) subSign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if w.Threshold == 0 {
		w.Threshold = 1
	}
	aopt, ok := opts.(*wltsign.Opts)
	if !ok {
		return nil, errors.New("sign requires appropriate options")
	}
	msg := new(big.Int).SetBytes(digest)
	keys := aopt.Keys

	// Prepare party IDs for TSS signing
	var ids tss.UnSortedPartyIDs
	m := make(map[string]tssPartyUpdateOnly)
	idmap := make(map[int]*tss.PartyID)
	for n, kd := range keys {
		p := w.getKey(kd.Id)
		if p == nil {
			return nil, fmt.Errorf("could not find key id=%s", kd.Id)
		}
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		ids = append(ids, id)
		idmap[n] = id
	}
	sids := tss.SortPartyIDs(ids)

	// Get the correct curve for the wallet
	curve, ok := tss.GetCurveByName(tss.CurveName(w.Curve))
	if !ok {
		return nil, fmt.Errorf("unknown curve %s", w.Curve)
	}
	tssctx := tss.NewPeerContext(sids)

	// Create channels for TSS communication
	outCh := make(chan tss.Message)
	defer close(outCh)
	res := make(chan any, len(keys))

	if w.Curve == "ed25519" {
		// EdDSA signing path
		for n, kd := range keys {
			p := w.getKey(kd.Id)
			if p == nil {
				return nil, fmt.Errorf("could not find key id=%s", kd.Id)
			}
			endCh := make(chan *common.SignatureData)
			params := tss.NewParameters(curve, tssctx, idmap[n], len(keys), w.Threshold)
			eddata, err := p.decryptEdDSA(kd, keySignPurpose)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt eddsa key %s for signing: %w", kd.Id, err)
			}
			party := eddsasigning.NewLocalParty(msg, params, *eddata, outCh, endCh, len(digest))
			m[p.Id.String()] = party
			go func(p *WalletKey) {
				defer func() {
					wltcrash.Log(aopt.Context, recover(), "eddsa signing party thread")
				}()
				err := party.Start()
				if err != nil {
					log.Printf("err = %s", err)
					res <- err
					return
				}
				sig := <-endCh
				// Ed25519 signature is R (32 bytes) || S (32 bytes)
				res <- sig.GetSignature()
			}(p)
		}
	} else {
		// ECDSA signing path
		for n, kd := range keys {
			p := w.getKey(kd.Id)
			if p == nil {
				return nil, fmt.Errorf("could not find key id=%s", kd.Id)
			}
			endCh := make(chan *common.SignatureData)
			params := tss.NewParameters(curve, tssctx, idmap[n], len(keys), w.Threshold)
			sdata, err := p.decrypt(kd, keySignPurpose)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt key %s for signing: %w", kd.Id, err)
			}
			party := ecdsasigning.NewLocalPartyWithAutoKDD(msg, params, *sdata, aopt.IL, outCh, endCh, len(digest))
			m[p.Id.String()] = party
			go func(p *WalletKey) {
				defer func() {
					wltcrash.Log(aopt.Context, recover(), "signing party thread")
				}()
				err := party.Start()
				if err != nil {
					log.Printf("err = %s", err)
					res <- err
					return
				}
				sig := <-endCh
				res <- sig.GetSignatureObject().Serialize()
			}(p)
		}
	}
	go tssRouter(aopt.Context, m, outCh)

	// Set a timeout for the signing operation
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	// Wait for result or timeout
	select {
	case final := <-res:
		switch v := final.(type) {
		case error:
			return nil, v
		case []byte:
			return v, nil
		default:
			return nil, fmt.Errorf("invalid data type %T", v)
		}
	case <-timer.C:
		return nil, fmt.Errorf("signature operation timed out")
	}
}

// GetPubkey returns the wallet's public key as a secp256k1.PublicKey object
// Decodes the base64-encoded public key stored in the wallet
// Returns the public key and any error encountered during decoding
func (w *Wallet) GetPubkey() (*secp256k1.PublicKey, error) {
	dat, err := base64.RawURLEncoding.DecodeString(w.Pubkey)
	if err != nil {
		return nil, err
	}
	return secp256k1.ParsePubKey(dat)
}
