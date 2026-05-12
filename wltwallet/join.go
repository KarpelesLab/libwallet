package wltwallet

// ClawdWallet Stage 1 — keygen-leader + sign-joiner static actions.
//
// Background. The legacy `Wallet:create` / `Wallet:multiCreate` flow is
// LEADER-driven: a single libwallet process owns all N TSS shares in
// process and stitches them together inside a single tssHub. Cross-host
// keygen on top of that requires an out-of-band identity-binding step
// (the existing SMS-OTP `remoteNew → remoteVerify → multiCreate` chain in
// remote.go) where libwallet asks the WalletSign backend to mint a
// `RemoteKey` blob and then drives a 3-party keygen that includes that
// remote as a TSS participant.
//
// ClawdWallet inverts the topology. The walletsign session row is opened
// SERVER-SIDE by the phplatform policy module (decision 2 in
// CLAWDWALLET_STAGE1.md): three Spot peers (mobile, agent, wdrone) are
// pinned in the row before any TSS round runs, and the row enters
// Status=valid the moment the policy module is happy with the request.
// Mobile (libwallet) therefore never calls `remoteVerify` — the OTP
// dance doesn't apply.
//
// Integration-phase contract (from CLAWDWALLET_STAGE1.md "Integration
// phase decisions"): mobile is the *keygen leader*. The integration
// audit found that all three TSS parties (mobile, agent, wdrone) had
// shipped joiner-only handlers — nobody was sending the bootstrap
// `walletsign/<sid>/init` message. Mobile takes that role: it
// constructs the canonical InitPayload, sends it to agent + wdrone over
// the same walletsign transport, then runs its own keygen LocalParty.
// The agent leads the sign side (mobile is not a signer in the 2-of-3
// scheme), so `joinSign` here remains joiner-only.
//
// Wire convention is identical to the production reshare path:
//   - recipient `<peer-spot-id>/walletsign/<sid>/[init|broadcast|single]`
//   - sender `<my-spot-id>/<sid>/<my-party-id>`
//
// (The sender form uses the canonical `<my_spot_id>/<sid>/<party_id>`
// shape per the integration-phase decision; the previous leading-slash
// form was an artefact of joiner-only code.)
//
// Stage 1 is ed25519-only. The shape generalises trivially to secp256k1
// when needed — drop in `ecdsatss.NewKeygen` / `NewSigning` against the
// same hub.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/tss-lib/v2/eddsatss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/xuid"
)

func init() {
	pobj.RegisterStatic("Wallet:initiateKeygen", apiInitiateKeygen)
	pobj.RegisterStatic("Wallet:joinSign", apiJoinSign)
}

// joinPeer is one participant in a ClawdWallet walletsign ceremony, as
// described on the wire. Matches the canonical InitPayload peers entry
// (see CLAWDWALLET_STAGE1.md "Integration phase decisions"):
//
//   - SpotId addresses the peer on the Spot network ("k.<base64>").
//   - Moniker is a stable human-readable tag carried inside the
//     tss-lib PartyID. The caller is REQUIRED to appear in this list —
//     join logic uses Moniker matching against an explicit `me` hint,
//     or falls back to SpotId == local TargetId.
//   - Key is base64url(raw Ed25519 pubkey bytes) of the peer's Spot
//     identity. All three parties MUST derive PartyID.Key from the
//     same bytes so SortedPartyIDs agrees across the committee —
//     this matches wdrone's existing convention (party.go:124-135).
type joinPeer struct {
	// SpotId carries the peer's Spot TargetId ("k.<base64url>"). JSON tag
	// is `id` so the wire shape matches tss-lib's MessageWrapper_PartyID
	// protobuf JSON tag — wdrone unmarshals the peers list directly into
	// tss.SortedPartyIDs and needs `id` populated for routing.
	SpotId  string `json:"id"`
	Moniker string `json:"moniker"`
	Key     string `json:"key"`
}

// initiateKeygenInput is the wire shape for Wallet:initiateKeygen.
//
//   - RemoteKey: the `<crws-id>:<crwsv-id>` string the policy module
//     returned from Crypto/WalletSign:verify. Already Status=valid
//     server-side; libwallet does NOT call remoteVerify in this flow.
//   - Peers: the full committee, passed through verbatim from
//     phplatform's :create response.
//   - WdroneSpotId: redundant with Peers (the wdrone entry is in
//     there), but accepted as an explicit reminder during integration.
//   - Curve: defaults to "ed25519" for Stage 1.
//   - MeMoniker: optional override for selecting the local party.
type initiateKeygenInput struct {
	RemoteKey    string      `json:"remote_key"`
	Peers        []*joinPeer `json:"peers"`
	WdroneSpotId string      `json:"wdrone_spot_id"`
	Name         string      `json:"name"`
	Curve        string      `json:"curve"`
	MeMoniker    string      `json:"me_moniker"`
}

type initiateKeygenResult struct {
	WltId         string `json:"wlt_id"`
	SolanaAddress string `json:"solana_address"`
	Pubkey        string `json:"pubkey"`
}

// joinSignInput is the wire shape for Wallet:joinSign. WltId points at a
// previously-joined wallet whose mobile share is already persisted
// locally; Digest is the 32-byte payload to sign (base64). The session
// row identified by RemoteKey must already be Status=valid server-side
// (the policy module decided to co-sign).
type joinSignInput struct {
	WltId     string      `json:"wlt_id"`
	RemoteKey string      `json:"remote_key"`
	Peers     []*joinPeer `json:"peers"`
	Curve     string      `json:"curve"`
	Digest    string      `json:"digest"`
	MeMoniker string      `json:"me_moniker"`
}

type joinSignResult struct {
	Signature string `json:"signature"`
}

// initPayload is the canonical JSON body of `walletsign/<sid>/init`
// (CLAWDWALLET_STAGE1.md "Integration phase decisions"). The leader
// (mobile for keygen, agent for sign) sends this to each non-self peer.
// wdrone falls back to the same shape stored in the Verify row's Data
// column.
type initPayload struct {
	Sid       string      `json:"sid"`
	Type      string      `json:"type"`
	Curve     string      `json:"curve"`
	Threshold int         `json:"threshold"`
	Peers     []*joinPeer `json:"peers"`
	Digest    string      `json:"digest,omitempty"`
}

// sidFromRemoteKey extracts the walletsign session id out of a
// `<crws-id>:<crwsv-id>` RemoteKey. The session id is the `crwsv-*`
// suffix — that's the row in Crypto_WalletSign_Verify wdrone polls via
// Crypto/WalletSign:checkKey, and the second path segment in all
// walletsign recipient paths. If the RemoteKey contains no ":", the
// whole string is treated as a sid (defensive, matches what the existing
// WalletKey.Key field carries pre-Stage-1).
func sidFromRemoteKey(rk string) string {
	if i := strings.IndexByte(rk, ':'); i >= 0 {
		return rk[i+1:]
	}
	return rk
}

// peerKeyInt decodes a peer's `key` field (base64url Ed25519 pubkey
// bytes) into the *big.Int that tss-lib uses for SortedPartyIDs
// ordering. Every party MUST derive this value from the same bytes
// (matching wdrone/party.go:124-135). Empty/garbage keys produce an
// explicit error so the SortedPartyIDs mismatch is caught at the
// caller, not deep inside a failed TSS round.
func peerKeyInt(p *joinPeer) (*big.Int, error) {
	if p == nil || p.Key == "" {
		return nil, fmt.Errorf("peer %q missing key field (need base64url Ed25519 pubkey bytes)", p.Moniker)
	}
	b, err := base64.RawURLEncoding.DecodeString(p.Key)
	if err != nil {
		// Tolerate the std encoding too in case the source serialised
		// with padding. The bytes are what matter, not the flavour.
		b2, err2 := base64.StdEncoding.DecodeString(p.Key)
		if err2 != nil {
			return nil, fmt.Errorf("peer %q has invalid base64 key: %w", p.Moniker, err)
		}
		b = b2
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("peer %q has empty key bytes", p.Moniker)
	}
	return new(big.Int).SetBytes(b), nil
}

// buildPartyIDs turns the canonical peer list into a SortedPartyIDs plus
// the index of the local party.
//
// Per integration-phase decision, PartyID.Key is derived from the
// peer's `key` field — base64url-decoded raw Ed25519 pubkey bytes —
// NOT from moniker bytes. This matches the convention used by wdrone
// (party.go:124-135) so all three parties agree on the canonical
// SortedPartyIDs ordering.
//
// PartyID.Id and PartyID.Moniker both carry the peer Moniker for
// human-readable diagnostics. (tss-lib uses .Key for sorting; .Id and
// .Moniker are display strings.)
//
// meSpotId / meMoniker pick out the local party — meMoniker wins if
// non-empty so the caller can be explicit (useful pre-online).
func buildPartyIDs(peers []*joinPeer, meSpotId, meMoniker string) (tss.SortedPartyIDs, map[string]*joinPeer, int, error) {
	if len(peers) < 2 {
		return nil, nil, -1, fmt.Errorf("buildPartyIDs: need at least 2 peers, got %d", len(peers))
	}
	ids := make(tss.UnSortedPartyIDs, 0, len(peers))
	byMoniker := make(map[string]*joinPeer, len(peers))
	for _, p := range peers {
		if p == nil || p.Moniker == "" {
			return nil, nil, -1, errors.New("buildPartyIDs: peer with empty moniker")
		}
		if _, dup := byMoniker[p.Moniker]; dup {
			return nil, nil, -1, fmt.Errorf("buildPartyIDs: duplicate moniker %s", p.Moniker)
		}
		byMoniker[p.Moniker] = p
		key, err := peerKeyInt(p)
		if err != nil {
			return nil, nil, -1, err
		}
		ids = append(ids, tss.NewPartyID(p.Moniker, p.Moniker, key))
	}
	sids := tss.SortPartyIDs(ids)

	meIdx := -1
	if meMoniker != "" {
		for i, id := range sids {
			if id.Moniker == meMoniker {
				meIdx = i
				break
			}
		}
	}
	if meIdx == -1 && meSpotId != "" {
		for i, id := range sids {
			if p := byMoniker[id.Moniker]; p != nil && p.SpotId == meSpotId {
				meIdx = i
				break
			}
		}
	}
	if meIdx == -1 {
		return nil, nil, -1, fmt.Errorf("buildPartyIDs: caller not in peer list (spot=%q moniker=%q)", meSpotId, meMoniker)
	}
	return sids, byMoniker, meIdx, nil
}

// apiInitiateKeygen runs the leader-side ClawdWallet keygen ceremony.
//
// Leader responsibilities (per integration-phase decision):
//  1. Build the canonical InitPayload from the caller-provided peer list.
//  2. Arm the inbound walletsign handler BEFORE sending any init message
//     (handler-vs-frame race mitigation: any peer that replies with a TSS
//     round-1 frame the instant it processes init must find a handler
//     waiting on this side).
//  3. Send `<peer>/walletsign/<sid>/init` to each non-self peer carrying
//     the InitPayload as JSON body.
//  4. Run mobile's own eddsatss.NewKeygen LocalParty against the shared
//     spotBroker — same machinery as the existing joiner path.
//  5. On completion: EnsureEd25519Pubkey self-heal, persist the share,
//     return the wallet id / solana address / pubkey to the caller.
func apiInitiateKeygen(ctx *apirouter.Context, in initiateKeygenInput) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if in.RemoteKey == "" {
		return nil, errors.New("remote_key is required")
	}
	if in.WdroneSpotId == "" {
		return nil, errors.New("wdrone_spot_id is required")
	}
	curve := in.Curve
	if curve == "" {
		curve = "ed25519"
	}
	if curve != "ed25519" {
		// Stage 1 is ed25519-only. The structure below generalises to
		// secp256k1 by swapping eddsatss for ecdsatss and pre-generating
		// LocalPreParams, but no Stage 1 caller needs it.
		return nil, fmt.Errorf("initiateKeygen: curve %q not supported in Stage 1 (ed25519 only)", curve)
	}

	spot, err := envSpot(ctx)
	if err != nil {
		return nil, fmt.Errorf("initiateKeygen: failed to get spot client: %w", err)
	}
	if err := waitOnlineSpot(spot); err != nil {
		return nil, fmt.Errorf("initiateKeygen: spot not online: %w", err)
	}
	meSpotId := spot.TargetId()

	sids, byMoniker, meIdx, err := buildPartyIDs(in.Peers, meSpotId, in.MeMoniker)
	if err != nil {
		return nil, err
	}
	sid := sidFromRemoteKey(in.RemoteKey)

	// Allocate the local wallet + the mobile's WalletKey. Type=RemoteKey
	// matches the existing remote_test.go:39-40 pattern: the share blob
	// is encrypted for the WalletSign backend keyring and recovered via
	// Crypto/WalletSign:pull during sign. wk.Id is purely a local
	// identifier — it does NOT cross the wire; the TSS PartyID is the
	// Moniker from the input peers list (so all three parties agree on
	// SortedPartyIDs).
	now := time.Now()
	wallet := &Wallet{
		Id:        xuid.New("wlt"),
		Name:      in.Name,
		Curve:     "ed25519",
		Threshold: 1,
		Created:   now,
		Modified:  now,
	}
	wk := &WalletKey{
		Id:     xuid.New("wkey"),
		Wallet: wallet.Id,
		Type:   "RemoteKey",
		Key:    in.RemoteKey,
		Gen:    1,
	}
	wallet.Keys = []*WalletKey{wk}
	wallet.Gen = 1

	curveEC := tss.Edwards()
	tssctx := tss.NewPeerContext(sids)
	hub := newTssHub()

	mePartyID := sids[meIdx]
	hub.addLocal(mePartyID)

	// Register a spotPeer per remote party. peer is populated up-front
	// (joiner mode in broker.Start) so we skip selectPeer + the legacy
	// reshare init handshake — ClawdWallet's session row is already
	// Status=valid and we drive the init handshake explicitly below.
	var remotes []*spotPeer
	for i, id := range sids {
		if i == meIdx {
			continue
		}
		p := byMoniker[id.Moniker]
		if p == nil || p.SpotId == "" {
			return nil, fmt.Errorf("initiateKeygen: peer %s missing spot_id", id.Moniker)
		}
		rp := &spotPeer{
			hub:     hub,
			partyId: id,
			info:    nil, // joiner-mode spotPeer: skip selectPeer + handshake
			spot:    spot,
			sid:     sid,
			peer:    p.SpotId,
			selfId:  meSpotId,
		}
		hub.addRemote(rp)
		remotes = append(remotes, rp)
	}

	// CRITICAL: register inbound handlers BEFORE sending init. The
	// integration audit found this race in the joiner-only world:
	// peers could start emitting round-1 frames the instant they
	// processed init, and if the leader hadn't yet armed its handler
	// those frames would be dropped on the floor.
	//
	// spotPeer.Start() in joiner mode is idempotent and only calls
	// spot.SetHandler(sid, ...) — safe to run before the broker has
	// any state.
	for _, rp := range remotes {
		if err := rp.Start(); err != nil {
			return nil, fmt.Errorf("initiateKeygen: failed to arm peer handler %s: %w", rp.partyId.Id, err)
		}
	}

	// Build + send the canonical InitPayload to every non-self peer.
	// We send the input peer list verbatim — the upstream phplatform
	// :create response is the source of truth for spot_id/moniker/key
	// triples, and we MUST NOT recompute the `key` field locally (any
	// re-encoding here would diverge from what the policy module wrote
	// to the Verify row's Data column).
	ip := &initPayload{
		Sid:       sid,
		Type:      "keygen",
		Curve:     "ed25519",
		Threshold: wallet.Threshold,
		Peers:     in.Peers,
	}
	ipBody, err := json.Marshal(ip)
	if err != nil {
		return nil, fmt.Errorf("initiateKeygen: marshal init payload: %w", err)
	}
	sendCtx, sendCancel := context.WithTimeout(ctx, 30*time.Second)
	for _, rp := range remotes {
		tgt := rp.peer + "/walletsign/" + sid + "/init"
		sender := meSpotId + "/" + sid + "/" + mePartyID.Id
		if err := spot.SendToWithFrom(sendCtx, tgt, ipBody, sender); err != nil {
			sendCancel()
			return nil, fmt.Errorf("initiateKeygen: send init to %s: %w", rp.peer, err)
		}
		log.Printf("initiateKeygen: sent init to %s/walletsign/%s/init", rp.peer, sid)
	}
	sendCancel()

	// PartyCount = total committee, threshold = 1 (Stage 1 — same as
	// existing initializeEdDSAWallet).
	params := tss.NewParameters(curveEC, tssctx, mePartyID, len(sids), wallet.Threshold)
	params.SetBroker(hub.local[mePartyID.Id])

	kg, err := eddsatss.NewKeygen(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("initiateKeygen: failed to start eddsa keygen: %w", err)
	}

	// Bound the wait so a missing peer doesn't pin the request forever.
	// 5 minutes covers a cold-start mobile + agent + wdrone HSM handshake
	// with plenty of slack.
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()

	var keyData *eddsatss.Key
	select {
	case keyData = <-kg.Done:
		// fallthrough
	case err := <-kg.Err:
		return nil, fmt.Errorf("initiateKeygen: eddsa keygen failed: %w", err)
	case <-ctx.Done():
		return nil, fmt.Errorf("initiateKeygen: cancelled: %w", ctx.Err())
	case <-timer.C:
		return nil, errors.New("initiateKeygen: timed out waiting for committee")
	}
	if keyData == nil {
		return nil, errors.New("initiateKeygen: eddsa keygen produced no key")
	}
	wk.eddata = keyData

	// Persist the canonical compressed Ed25519 pubkey (the on-curve
	// serialization tss-lib actually signs with). The historical X-coord
	// encoding bug is repaired centrally by EnsureEd25519Pubkey, which we
	// call below after save — but we set the right value here too so
	// fresh wallets don't need the repair path.
	pubBytes := keyData.EDDSAPub.ToEd25519PubKey().Serialize()
	wallet.Pubkey = base64.RawURLEncoding.EncodeToString(pubBytes)

	// Encrypt the share. For Type=RemoteKey this uploads the share blob
	// to the WalletSign backend (encrypted to its keyring) via
	// Crypto/WalletSign:setGeneratedKey so wdrone can later pull it on
	// sign. Local copy stays in wk.Data.
	if err := wk.encrypt(&wltsign.KeyDescription{Type: "RemoteKey", Key: in.RemoteKey}); err != nil {
		return nil, fmt.Errorf("initiateKeygen: failed to encrypt share: %w", err)
	}

	if err := wallet.save(e); err != nil {
		return nil, fmt.Errorf("initiateKeygen: failed to save wallet: %w", err)
	}

	// Audit risk #3: always run the self-heal so wallets created on
	// older callers (or with a stale Pubkey for any reason) get
	// repaired. Safe no-op when Pubkey already matches the TSS
	// serialization.
	canonical, err := EnsureEd25519Pubkey(e, wallet, []*wltsign.KeyDescription{{Id: wk.Id.String(), Type: "RemoteKey", Key: in.RemoteKey}})
	if err != nil {
		log.Printf("initiateKeygen: EnsureEd25519Pubkey returned error (non-fatal): %s", err)
	} else if canonical != "" {
		wallet.Pubkey = canonical
	}

	// Solana address = base58(raw 32-byte ed25519 pubkey). Matches the
	// derivation in wltacct/account.go:309.
	rawPub, decErr := base64.RawURLEncoding.DecodeString(wallet.Pubkey)
	var solanaAddr string
	if decErr == nil && len(rawPub) == 32 {
		solanaAddr = base58.Bitcoin.Encode(rawPub)
	}

	return &initiateKeygenResult{
		WltId:         wallet.Id.String(),
		SolanaAddress: solanaAddr,
		Pubkey:        wallet.Pubkey,
	}, nil
}

func apiJoinSign(ctx *apirouter.Context, in joinSignInput) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}
	if in.WltId == "" {
		return nil, errors.New("wlt_id is required")
	}
	if in.RemoteKey == "" {
		return nil, errors.New("remote_key is required")
	}
	if in.Digest == "" {
		return nil, errors.New("digest is required")
	}
	digest, err := base64.StdEncoding.DecodeString(in.Digest)
	if err != nil {
		// Fall back to URL encoding to tolerate either flavour from the host.
		digest, err = base64.RawURLEncoding.DecodeString(in.Digest)
		if err != nil {
			return nil, fmt.Errorf("joinSign: invalid base64 digest: %w", err)
		}
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("joinSign: digest must be 32 bytes, got %d", len(digest))
	}
	curve := in.Curve
	if curve == "" {
		curve = "ed25519"
	}
	if curve != "ed25519" {
		return nil, fmt.Errorf("joinSign: curve %q not supported in Stage 1 (ed25519 only)", curve)
	}

	wltId, err := xuid.ParsePrefix(in.WltId, "wlt")
	if err != nil {
		return nil, fmt.Errorf("joinSign: invalid wlt_id: %w", err)
	}
	wallet, err := WalletById(e, wltId)
	if err != nil {
		return nil, fmt.Errorf("joinSign: wallet not found: %w", err)
	}
	if wallet.Curve != "ed25519" {
		return nil, fmt.Errorf("joinSign: wallet curve is %q, expected ed25519", wallet.Curve)
	}

	// The mobile share is the single RemoteKey-typed WalletKey on this
	// wallet (matching what initiateKeygen wrote). Find it.
	var localKey *WalletKey
	for _, k := range wallet.Keys {
		if k.Type == "RemoteKey" && k.Key == in.RemoteKey {
			localKey = k
			break
		}
	}
	if localKey == nil {
		// Tolerate the case where RemoteKey rotates: pick the first
		// RemoteKey-typed share. Wdrone re-encrypts payloads under the
		// same key id during reshare, so the Key field on the share
		// might lag behind the active session id — falling back keeps
		// joinSign usable.
		for _, k := range wallet.Keys {
			if k.Type == "RemoteKey" {
				localKey = k
				break
			}
		}
	}
	if localKey == nil {
		return nil, errors.New("joinSign: no RemoteKey share on wallet")
	}

	spot, err := envSpot(ctx)
	if err != nil {
		return nil, fmt.Errorf("joinSign: failed to get spot client: %w", err)
	}
	if err := waitOnlineSpot(spot); err != nil {
		return nil, fmt.Errorf("joinSign: spot not online: %w", err)
	}
	meSpotId := spot.TargetId()

	sids, byMoniker, meIdx, err := buildPartyIDs(in.Peers, meSpotId, in.MeMoniker)
	if err != nil {
		return nil, err
	}
	sid := sidFromRemoteKey(in.RemoteKey)

	// Self-heal the persisted pubkey before signing — see the analogous
	// repair inside Wallet.subSign. Cheap and safe to run every time.
	_, _ = EnsureEd25519Pubkey(e, wallet, []*wltsign.KeyDescription{{Id: localKey.Id.String(), Type: "RemoteKey", Key: in.RemoteKey}})

	eddata, err := localKey.decryptEdDSA(&wltsign.KeyDescription{Id: localKey.Id.String(), Type: "RemoteKey", Key: in.RemoteKey}, keySignPurpose)
	if err != nil {
		return nil, fmt.Errorf("joinSign: failed to decrypt local share: %w", err)
	}

	curveEC := tss.Edwards()
	tssctx := tss.NewPeerContext(sids)
	hub := newTssHub()

	mePartyID := sids[meIdx]
	hub.addLocal(mePartyID)

	var remotes []*spotPeer
	for i, id := range sids {
		if i == meIdx {
			continue
		}
		p := byMoniker[id.Moniker]
		if p == nil || p.SpotId == "" {
			return nil, fmt.Errorf("joinSign: peer %s missing spot_id", id.Moniker)
		}
		rp := &spotPeer{
			hub:     hub,
			partyId: id,
			info:    nil,
			spot:    spot,
			sid:     sid,
			peer:    p.SpotId,
			selfId:  meSpotId,
		}
		hub.addRemote(rp)
		remotes = append(remotes, rp)
	}
	for _, rp := range remotes {
		if err := rp.Start(); err != nil {
			return nil, fmt.Errorf("joinSign: failed to start peer %s: %w", rp.partyId.Id, err)
		}
	}

	params := tss.NewParameters(curveEC, tssctx, mePartyID, len(sids), wallet.Threshold)
	params.SetBroker(hub.local[mePartyID.Id])

	msg := new(big.Int).SetBytes(digest)
	sg, err := eddata.NewSigning(ctx, msg, params)
	if err != nil {
		return nil, fmt.Errorf("joinSign: failed to start eddsa signing: %w", err)
	}

	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()

	select {
	case sd := <-sg.Done:
		if len(sd.Signature) != 64 {
			return nil, fmt.Errorf("joinSign: expected 64-byte signature, got %d", len(sd.Signature))
		}
		return &joinSignResult{
			Signature: base64.StdEncoding.EncodeToString(sd.Signature),
		}, nil
	case err := <-sg.Err:
		return nil, fmt.Errorf("joinSign: eddsa signing failed: %w", err)
	case <-ctx.Done():
		return nil, fmt.Errorf("joinSign: cancelled: %w", ctx.Err())
	case <-timer.C:
		return nil, errors.New("joinSign: timed out waiting for committee")
	}
}
