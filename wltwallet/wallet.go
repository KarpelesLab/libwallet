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

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltcrash"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltlog"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/secp256k1"
	"github.com/KarpelesLab/tss-lib/v2/dklstss"
	"github.com/KarpelesLab/tss-lib/v2/ecdsatss"
	"github.com/KarpelesLab/tss-lib/v2/eddsatss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

// Wallet represents a multi-signature wallet with threshold signature scheme (TSS) support
// It can contain multiple keys with a configurable threshold for signatures
type Wallet struct {
	TableName psql.Name    `sql:"Wallet"`
	Id        *xuid.XUID   `sql:",key=PRIMARY"`                              // Unique identifier for the wallet
	Name      string       `sql:",type=VARCHAR,size=255"`                    // User-friendly name
	Curve     string       `sql:",type=VARCHAR,size=255"`                    // Elliptic curve used (e.g., "secp256k1")
	Protocol  string       `sql:",type=VARCHAR,size=64,null=0,default=''"`   // TSS protocol — see ProtocolFor* constants. Empty = legacy (gg18 / eddsa).
	Threshold int          `sql:",type=INT"`                                 // Minimum number of keys required for signing
	Keys      []*WalletKey `sql:"-"`                                         // Associated keys (not stored in database)
	Gen       uint64       `sql:",type=BIGINT,null=0,default=0"`             // incremented on reshare
	Pubkey    string       `sql:",type=TEXT"`                                // Base64 encoded public key
	Chaincode string       `sql:",type=TEXT"`                                // Base64 encoded chaincode for HD wallet derivation
	Created   time.Time    `sql:",type=DATETIME"`                            // Creation timestamp
	Modified  time.Time    `sql:",type=DATETIME"`                            // Last modification timestamp
}

// TSS protocol identifiers stored in [Wallet.Protocol]. The value
// determines which keygen / sign / reshare path libwallet runs for
// the wallet — once set at keygen time, it stays for the lifetime of
// the wallet because the persisted key shares are protocol-specific.
//
// Empty string matches the historical wallet rows that pre-date this
// field; it's treated identically to the legacy constants below by
// every dispatch site. New wallets created today land with one of the
// modern values.
const (
	// ProtocolLegacyECDSA — secp256k1 wallets that use tss-lib's GG18
	// implementation (the ecdsatss package). Empty Protocol on a
	// secp256k1 wallet maps to this.
	ProtocolLegacyECDSA = "gg18"
	// ProtocolLegacyEdDSA — ed25519 wallets that use tss-lib's
	// eddsatss package (GG18-style Schnorr). Empty Protocol on an
	// ed25519 wallet maps to this.
	ProtocolLegacyEdDSA = "eddsa"

	// ProtocolDKLS — modern secp256k1 path via DKLs23 (dklstss).
	// Drops the Paillier/MtA layer, sidestepping the GG18 attack
	// surface (TSSHOCK, Alpha-Rays, etc.). Used for new secp256k1
	// wallets.
	ProtocolDKLS = "dkls23"
	// ProtocolFROST — modern ed25519 path via FROST (RFC 9591, the
	// frosttss package). Used for new ed25519 wallets.
	ProtocolFROST = "frost"
)

// resolveProtocol returns the effective protocol for the wallet,
// substituting the curve-appropriate legacy value when [Wallet.Protocol]
// is empty. Callsites should branch on the resolved value — never the
// raw field — so existing rows continue to route through the legacy
// keygen / sign paths.
func (w *Wallet) resolveProtocol() string {
	if w == nil {
		return ""
	}
	if w.Protocol != "" {
		return w.Protocol
	}
	switch w.Curve {
	case "secp256k1":
		return ProtocolLegacyECDSA
	case "ed25519":
		return ProtocolLegacyEdDSA
	}
	return ""
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
	if err := psql.Replace(e, w); err != nil {
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
	if _, err := psql.ForceDelete[WalletKey](e, map[string]any{"Wallet": w.Id.String()}); err != nil {
		return fmt.Errorf("failed to delete wallet keys for wallet %s: %w", w.Id, err)
	}

	if _, err := psql.ForceDelete[Wallet](e, map[string]any{"Id": w.Id}); err != nil {
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
// Dispatches on Wallet.Protocol:
//   - empty / "gg18" → the historical ecdsatss (GG18) keygen below
//   - "dkls23"      → initializeDklsWallet (modern DKLs23, no Paillier)
//
// Returns any error encountered during wallet initialization
func (w *Wallet) initializeWallet(ctx context.Context, kDesc []*wltsign.KeyDescription) error {
	if w.Protocol == ProtocolDKLS {
		return w.initializeDklsWallet(ctx, kDesc)
	}
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

	// Progress tree: [0, nk/(nk+1)) = per-key pre-params, [nk/(nk+1), 1] = final keygen.
	root := newProgressScope(ctx)
	root.report(0)

	// Create wallet keys for each key description
	for i, kInfo := range kDesc {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
			// OK
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		log.Printf("generating key %d/%d", i, nk)

		k, err := w.createWalletKey(ctx, kInfo.Type, root.sub(i, nk+1))
		if err != nil {
			return fmt.Errorf("failed to create wallet key of type %s (key %d/%d): %w", kInfo.Type, i+1, nk, err)
		}
		w.Keys[i] = k
	}

	log.Printf("producing final")

	// Final keygen phase: its own slice of the progress range.
	finalScope := root.sub(nk, nk+1)
	finalScope.report(0)

	// Set up TSS parties for distributed key generation
	var ids tss.UnSortedPartyIDs
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

	// Register every local broker in the hub before any party starts so
	// round1 messages from an early party can queue on later parties.
	hub := newTssHub()
	for n := range w.Keys {
		hub.addLocal(idmap[n])
	}

	var wg sync.WaitGroup
	wg.Add(len(w.Keys))

	for n, p := range w.Keys {
		params := tss.NewParameters(curve, tssctx, idmap[n], nk, w.Threshold)
		params.SetBroker(hub.local[idmap[n].Id])
		kg, err := ecdsatss.NewKeygen(ctx, params, *p.pre)
		if err != nil {
			return fmt.Errorf("failed to start keygen for party %d: %w", n, err)
		}
		go func(p *WalletKey, kg *ecdsatss.Keygen) {
			defer wg.Done()
			select {
			case key := <-kg.Done:
				p.sdata = key
			case err := <-kg.Err:
				log.Printf("keygen err = %s", err)
				p.sdata = nil
			case <-ctx.Done():
				p.sdata = nil
			}
		}(p, kg)
	}

	// Generate random chaincode for HD wallet derivation
	chaincode := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, chaincode)
	if err != nil {
		return fmt.Errorf("failed to generate secure chaincode for wallet: %w", err)
	}

	// Wait for all key generation to complete
	wg.Wait()

	if w.Keys[0].sdata == nil {
		return errors.New("ecdsa key generation failed")
	}

	// Set wallet properties from generated keys
	pk := w.Keys[0].sdata.ECDSAPub.ToSecp256k1PubKey()
	w.Pubkey = base64.RawURLEncoding.EncodeToString(pk.SerializeCompressed())
	w.Chaincode = base64.RawURLEncoding.EncodeToString(chaincode)
	w.Curve = curve.Params().Name
	// Stamp the persisted Protocol so resolveProtocol() doesn't need
	// to infer it. New wallets created today still go through the
	// ecdsatss path; Step 3 of the protocol-modernization track will
	// add a Protocol=="dkls23" branch above this point.
	if w.Protocol == "" {
		w.Protocol = ProtocolLegacyECDSA
	}

	// Encrypt keys with their respective key descriptions
	for i, kInfo := range kDesc {
		err = w.Keys[i].encrypt(kInfo)
		if err != nil {
			return fmt.Errorf("failed to encrypt wallet key %d/%d of type %s: %w", i+1, len(w.Keys), kInfo.Type, err)
		}
	}

	finalScope.report(1)
	return nil
}

// initializeDklsWallet creates a new secp256k1 wallet using DKLs23 TSS.
//
// Mirrors initializeWallet's orchestration — N parties, local
// in-process broker hub, each share lands in WalletKey.dklsData and
// is encrypted into WalletKey.Data via the Schema="dkls23" path.
//
// Differences from the ecdsatss path:
//   - No LocalPreParams stage (dklstss doesn't use Paillier/MtA).
//   - dklstss.NewKeygen takes (ctx, params) only.
//   - The resulting share lives in WalletKey.dklsData (binary-Save
//     wrapped via dklsKeyWrapper at encrypt time).
//   - The joint public key is still on key.ECDSAPub (same field
//     name as ecdsatss).
//
// Caller responsibility: w.Protocol must be set to ProtocolDKLS before
// invoking this. initializeWallet dispatches here when that's true;
// direct callers should set the field explicitly.
func (w *Wallet) initializeDklsWallet(ctx context.Context, kDesc []*wltsign.KeyDescription) error {
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

	root := newProgressScope(ctx)
	root.report(0)

	// Allocate per-share WalletKey entries. DKLs23 doesn't need the
	// slow Paillier preparam stage that ecdsatss's createWalletKey
	// runs, so we don't call it — just stamp the row.
	for i, kInfo := range kDesc {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
			// OK
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		w.Keys[i] = &WalletKey{
			Id:     xuid.New("wkey"),
			Wallet: w.Id,
			Type:   kInfo.Type,
			Gen:    w.Gen + 1,
		}
		root.sub(i, nk+1).report(1)
	}

	finalScope := root.sub(nk, nk+1)
	finalScope.report(0)

	var ids tss.UnSortedPartyIDs
	idmap := make(map[int]*tss.PartyID)
	for n, p := range w.Keys {
		key := new(big.Int).SetBytes(p.Id.UUID[:])
		id := tss.NewPartyID(p.Id.String(), p.Id.String(), key)
		ids = append(ids, id)
		idmap[n] = id
	}
	sids := tss.SortPartyIDs(ids)

	curve := tss.S256()
	tssctx := tss.NewPeerContext(sids)

	hub := newTssHub()
	for n := range w.Keys {
		hub.addLocal(idmap[n])
	}

	var wg sync.WaitGroup
	wg.Add(len(w.Keys))
	for n, p := range w.Keys {
		params := tss.NewParameters(curve, tssctx, idmap[n], nk, w.Threshold)
		params.SetBroker(hub.local[idmap[n].Id])
		kg, err := dklstss.NewKeygen(ctx, params)
		if err != nil {
			return fmt.Errorf("failed to start dkls23 keygen for party %d: %w", n, err)
		}
		go func(p *WalletKey, kg *dklstss.KeygenParty) {
			defer wg.Done()
			select {
			case key := <-kg.Done:
				p.dklsData = key
			case err := <-kg.Err:
				log.Printf("dkls23 keygen err = %s", err)
				p.dklsData = nil
			case <-ctx.Done():
				p.dklsData = nil
			}
		}(p, kg)
	}

	// Random chaincode for HD derivation — same as the ecdsatss path.
	chaincode := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, chaincode); err != nil {
		return fmt.Errorf("failed to generate secure chaincode for wallet: %w", err)
	}

	wg.Wait()

	if w.Keys[0].dklsData == nil {
		return errors.New("dkls23 key generation failed")
	}

	pk := w.Keys[0].dklsData.ECDSAPub.ToSecp256k1PubKey()
	w.Pubkey = base64.RawURLEncoding.EncodeToString(pk.SerializeCompressed())
	w.Chaincode = base64.RawURLEncoding.EncodeToString(chaincode)
	w.Curve = "secp256k1"
	w.Protocol = ProtocolDKLS

	for i, kInfo := range kDesc {
		if err := w.Keys[i].encrypt(kInfo); err != nil {
			return fmt.Errorf("failed to encrypt dkls23 wallet key %d/%d of type %s: %w", i+1, len(w.Keys), kInfo.Type, err)
		}
	}
	finalScope.report(1)
	return nil
}

// initializeEdDSAWallet creates a new Ed25519 wallet using EdDSA TSS
func (w *Wallet) initializeEdDSAWallet(ctx context.Context, kDesc []*wltsign.KeyDescription) error {
	w.Curve = "ed25519"
	// Stamp Protocol so resolveProtocol() returns it directly on
	// reload. Step 4 will add a Protocol=="frost" branch.
	if w.Protocol == "" {
		w.Protocol = ProtocolLegacyEdDSA
	}
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

	root := newProgressScope(ctx)
	root.report(0)

	for i, kInfo := range kDesc {
		switch kInfo.Type {
		case "StoreKey", "Plain", "RemoteKey", "Password":
			// OK
		default:
			return fmt.Errorf("unsupported key type %s for key #%d", kInfo.Type, i+1)
		}
		log.Printf("generating eddsa key %d/%d", i, nk)

		k, err := w.createWalletKey(ctx, kInfo.Type, root.sub(i, nk+1))
		if err != nil {
			return fmt.Errorf("failed to create eddsa wallet key of type %s (key %d/%d): %w", kInfo.Type, i+1, nk, err)
		}
		w.Keys[i] = k
	}

	log.Printf("producing eddsa final")
	edFinalScope := root.sub(nk, nk+1)
	edFinalScope.report(0)

	var ids tss.UnSortedPartyIDs
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

	hub := newTssHub()
	for n := range w.Keys {
		hub.addLocal(idmap[n])
	}

	var wg sync.WaitGroup
	wg.Add(len(w.Keys))

	for n, p := range w.Keys {
		params := tss.NewParameters(curve, tssctx, idmap[n], nk, w.Threshold)
		params.SetBroker(hub.local[idmap[n].Id])
		kg, err := eddsatss.NewKeygen(ctx, params)
		if err != nil {
			return fmt.Errorf("failed to start eddsa keygen for party %d: %w", n, err)
		}
		go func(p *WalletKey, kg *eddsatss.Keygen) {
			defer wg.Done()
			select {
			case key := <-kg.Done:
				p.eddata = key
			case err := <-kg.Err:
				log.Printf("eddsa keygen err = %s", err)
				p.eddata = nil
			case <-ctx.Done():
				p.eddata = nil
			}
		}(p, kg)
	}

	chaincode := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, chaincode)
	if err != nil {
		return fmt.Errorf("failed to generate secure chaincode for wallet: %w", err)
	}

	wg.Wait()

	if w.Keys[0].eddata == nil {
		return errors.New("eddsa key generation failed")
	}

	// Extract Ed25519 public key using the standard compressed
	// encoding (32-byte little-endian Y with X-sign bit in MSB of
	// byte 31). Writing the X coordinate alone — what an earlier
	// version of this code did — produced an address that wasn't
	// the on-curve pubkey the TSS actually signs with, so Solana
	// rejected every send with "Transaction did not pass signature
	// verification" and balance queries hit a different address
	// from the one the TSS controls.
	pubBytes := w.Keys[0].eddata.EDDSAPub.ToEd25519PubKey().Serialize()
	w.Pubkey = base64.RawURLEncoding.EncodeToString(pubBytes)
	w.Chaincode = base64.RawURLEncoding.EncodeToString(chaincode)

	for i, kInfo := range kDesc {
		err = w.Keys[i].encrypt(kInfo)
		if err != nil {
			return fmt.Errorf("failed to encrypt eddsa wallet key %d/%d of type %s: %w", i+1, len(w.Keys), kInfo.Type, err)
		}
	}

	edFinalScope.report(1)
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

// EnsureEd25519Pubkey decrypts the first provided key to extract the
// canonical compressed-Y Ed25519 public key and compares it against
// Wallet.Pubkey. When they disagree (the legacy X-coord-big-endian
// encoding wallets created before the fix) the wallet is repaired,
// resaved, and wallet:pubkey_repaired is emitted so Account records
// linked to this wallet also get updated.
//
// Safe to call before every Ed25519 TSS signing flow — no-op when the
// wallet already has the correct pubkey. Returns the authoritative
// compressed pubkey (base64 RawURLEncoding).
func EnsureEd25519Pubkey(e wltintf.Env, w *Wallet, keys []*wltsign.KeyDescription) (string, error) {
	if w == nil || w.Curve != "ed25519" || len(keys) == 0 {
		if w != nil {
			return w.Pubkey, nil
		}
		return "", nil
	}
	kd := keys[0]
	wk := w.getKey(kd.Id)
	if wk == nil {
		return w.Pubkey, fmt.Errorf("key %s not in wallet %s", kd.Id, w.Id)
	}
	eddata, err := wk.decryptEdDSA(kd, keySignPurpose)
	if err != nil {
		return w.Pubkey, err
	}
	want := base64.RawURLEncoding.EncodeToString(eddata.EDDSAPub.ToEd25519PubKey().Serialize())
	if w.Pubkey == want {
		return want, nil
	}
	w.Pubkey = want
	if err := w.save(e); err != nil {
		return want, err
	}
	if em := e.Emitter(); em != nil {
		em.Emit(context.Background(), "wallet:pubkey_repaired", map[string]string{
			"wallet": w.Id.String(),
			"pubkey": want,
		})
	}
	return want, nil
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
	// Imported single-share wallets (RawKey / MnemonicKey) bypass the
	// TSS signing protocol — there's only one party and it holds the
	// full private key, so the 9-round MTA dance would be wasted work.
	// Same DER output shape on the way out, so callers (Account.Sign,
	// SignEthereumDigest, SignBitcoinMessage, etc.) don't branch.
	if len(w.Keys) == 1 && (w.Keys[0].Schema == "raw" || w.Keys[0].Schema == "mnemonic") {
		dat, err = w.signRaw(rand, digest, opts)
		return
	}
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

	signCtx := aopt.Context
	if signCtx == nil {
		signCtx = context.Background()
	}

	// Prepare party IDs for TSS signing
	var ids tss.UnSortedPartyIDs
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

	hub := newTssHub()
	for n := range keys {
		hub.addLocal(idmap[n])
	}

	res := make(chan any, len(keys))

	if w.resolveProtocol() == ProtocolDKLS {
		wltlog.Debugf("wallet-sign: dkls23 id=%s threshold=%d keys_provided=%d msg_len=%d", w.Id, w.Threshold, len(keys), len(digest))
		// dklstss requires the subset to be exactly T+1; surface that
		// here rather than letting NewSigning return a less obvious
		// "subset size N, expected T+1=M" error per party.
		if len(keys) != w.Threshold+1 {
			return nil, fmt.Errorf("dkls23: signing requires exactly T+1=%d signers, got %d", w.Threshold+1, len(keys))
		}
		for n, kd := range keys {
			p := w.getKey(kd.Id)
			if p == nil {
				return nil, fmt.Errorf("could not find key id=%s", kd.Id)
			}
			// dklstss only reads PartyID/EC/Broker/Rand from params; N/T
			// come from the embedded key. The shared idmap/sids/hub set
			// up above already represent this subset.
			params := tss.NewParameters(curve, tssctx, idmap[n], len(keys), w.Threshold)
			params.SetBroker(hub.local[idmap[n].Id])
			dklsKey, err := p.decryptDkls(kd, keySignPurpose)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt dkls23 key %s for signing: %w", kd.Id, err)
			}
			sp, err := dklstss.NewSigning(signCtx, params, dklsKey, digest, sids, aopt.IL)
			if err != nil {
				return nil, fmt.Errorf("failed to start dkls23 signing for key %s: %w", kd.Id, err)
			}
			go func() {
				defer func() {
					wltcrash.Log(signCtx, recover(), "dkls23 signing party thread")
				}()
				select {
				case sig := <-sp.Done:
					res <- dklsDERFromSignature(sig)
				case err := <-sp.Err:
					res <- err
				case <-signCtx.Done():
					res <- signCtx.Err()
				}
			}()
		}
	} else if w.Curve == "ed25519" {
		wltlog.Debugf("wallet-sign: ed25519 id=%s threshold=%d keys_provided=%d msg_len=%d", w.Id, w.Threshold, len(keys), len(digest))
		// Self-heal Pubkey for wallets created before the X-coord →
		// compressed-Y encoding fix. The persisted Pubkey is
		// authoritative; if it doesn't match the on-curve serialization
		// of the (soon-to-be-decrypted) EDDSAPub, we'd sign with the
		// real key but emit a tx with the wrong pubkey → Solana
		// rejects with "Transaction did not pass signature verification".
		// Repair done once per sign, after the first key decrypts.
		var repairedPubkey bool
		for n, kd := range keys {
			p := w.getKey(kd.Id)
			if p == nil {
				return nil, fmt.Errorf("could not find key id=%s", kd.Id)
			}
			params := tss.NewParameters(curve, tssctx, idmap[n], len(keys), w.Threshold)
			params.SetBroker(hub.local[idmap[n].Id])
			decStart := time.Now()
			eddata, err := p.decryptEdDSA(kd, keySignPurpose)
			if err != nil {
				wltlog.Errorf("wallet-sign: ed25519 decrypt key %s failed after %s: %s", kd.Id, time.Since(decStart).Round(time.Millisecond), err)
				return nil, fmt.Errorf("failed to decrypt eddsa key %s for signing: %w", kd.Id, err)
			}
			wltlog.Debugf("wallet-sign: ed25519 key %s decrypted in %s (type=%s)", kd.Id, time.Since(decStart).Round(time.Millisecond), p.Type)
			if !repairedPubkey {
				repairedPubkey = true
				want := base64.RawURLEncoding.EncodeToString(eddata.EDDSAPub.ToEd25519PubKey().Serialize())
				if w.Pubkey != want {
					wltlog.Warnf("wallet-sign: ed25519 Pubkey mismatch on wallet %s — persisted %q but TSS says %q (repairing)", w.Id, w.Pubkey, want)
					w.Pubkey = want
					// aopt.Context is an *apirouter.Context (or any
					// context.Context); the Env is attached as an
					// object on it — use GetEnv to retrieve it. The
					// earlier direct type-assertion never matched.
					if env := wltintf.GetEnv(aopt.Context); env != nil {
						// non-fatal: if the save fails, the next
						// sign attempt will retry the repair.
						_ = w.save(env)
						// Linked Account records cached the old
						// Pubkey at init; emit so wltacct can
						// propagate the fix.
						if em := env.Emitter(); em != nil {
							em.Emit(context.Background(), "wallet:pubkey_repaired", map[string]string{
								"wallet": w.Id.String(),
								"pubkey": want,
							})
						}
					}
				}
			}
			sg, err := eddata.NewSigning(signCtx, msg, params)
			if err != nil {
				return nil, fmt.Errorf("failed to start eddsa signing for key %s: %w", kd.Id, err)
			}
			go func() {
				defer func() {
					wltcrash.Log(signCtx, recover(), "eddsa signing party thread")
				}()
				select {
				case sig := <-sg.Done:
					res <- sig.Signature
				case err := <-sg.Err:
					res <- err
				case <-signCtx.Done():
					res <- signCtx.Err()
				}
			}()
		}
	} else {
		for n, kd := range keys {
			p := w.getKey(kd.Id)
			if p == nil {
				return nil, fmt.Errorf("could not find key id=%s", kd.Id)
			}
			params := tss.NewParameters(curve, tssctx, idmap[n], len(keys), w.Threshold)
			params.SetBroker(hub.local[idmap[n].Id])
			sdata, err := p.decrypt(kd, keySignPurpose)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt key %s for signing: %w", kd.Id, err)
			}
			sg, err := sdata.NewSigningWithKDD(signCtx, msg, params, aopt.IL)
			if err != nil {
				return nil, fmt.Errorf("failed to start ecdsa signing for key %s: %w", kd.Id, err)
			}
			go func() {
				defer func() {
					wltcrash.Log(signCtx, recover(), "signing party thread")
				}()
				select {
				case sig := <-sg.Done:
					res <- ecdsaDERFromSigData(sig)
				case err := <-sg.Err:
					res <- err
				case <-signCtx.Done():
					res <- signCtx.Err()
				}
			}()
		}
	}

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

// ecdsaDERFromSigData builds a DER-encoded ECDSA signature from the new
// ecdsatss.SignatureData shape. Matches the output of the old
// common.SignatureData.GetSignatureObject().Serialize() path.
func ecdsaDERFromSigData(sd *ecdsatss.SignatureData) []byte {
	var r, s secp256k1.ModNScalar
	r.SetByteSlice(sd.R)
	s.SetByteSlice(sd.S)
	return secp256k1.NewSignatureWithRecoveryCode(&r, &s, sd.Recovery&1).Serialize()
}

// dklsDERFromSignature emits the same DER shape as ecdsaDERFromSigData so
// callers (Account.Sign, SignEthereumDigest, etc.) don't branch on the
// underlying TSS protocol.
func dklsDERFromSignature(sig *dklstss.Signature) []byte {
	var r, s secp256k1.ModNScalar
	r.SetByteSlice(sig.R.Bytes())
	s.SetByteSlice(sig.S.Bytes())
	return secp256k1.NewSignatureWithRecoveryCode(&r, &s, sig.V&1).Serialize()
}
