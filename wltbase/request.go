package wltbase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/libwallet/wltutil"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
	"golang.org/x/crypto/sha3"
)

func init() {
	pobj.RegisterActions[request]("Request",
		&pobj.ObjectActions{
			Fetch: pobj.Static(apiFetchRequest),
			List:  pobj.Static(apiListRequest),
		},
	)

	pobj.RegisterStatic("Request:test", requestTestReq)
	pobj.RegisterStatic("Request:approve", requestDoApprove)
	pobj.RegisterStatic("Request:reject", requestDoReject)
}

var (
	pendingReqs   = make(map[string]chan string)
	pendingReqsLk sync.Mutex
)

type request struct {
	psql.Name   `sql:"Request"`
	Id          *xuid.XUID         `sql:",key=PRIMARY"`
	Type        string             `sql:",type=VARCHAR,size=255"`                   // connect | sign | add_network | change_network | test
	Host        string             `sql:",type=VARCHAR,size=255"`                   // URL of requesting site
	Status      string             `sql:",type=VARCHAR,size=255"`                   // pending | accepted | rejected | timedout
	Account     *string            `sql:",type=VARCHAR,size=255"`                   // account used for signature, if specified
	Transaction *wlttx.Transaction `json:",omitempty" sql:",type=JSON,format=json"` // if Type=sign, contains the transaction to be signed
	Value       any                `json:",omitempty" sql:",type=JSON,format=json"` // generic value
	Result      any                `json:",omitempty" sql:",type=JSON,format=json"` // generic response
	Created     time.Time          `sql:",type=DATETIME"`
	Updated     time.Time          `sql:",type=DATETIME"`
}

func (r *request) save(e *env) error {
	if r.Id == nil {
		// compute id
		r.Id = xuid.Must(xuid.NewRandom("req"))
	}
	now := time.Now()
	if r.Created.IsZero() {
		r.Created = now
	}
	r.Updated = now
	return psql.Replace(e.sqlCtx, r)
}

func makePendingRequestChan(id string) chan string {
	ch := make(chan string)
	pendingReqsLk.Lock()
	defer pendingReqsLk.Unlock()

	if c, ok := pendingReqs[id]; ok {
		close(c)
	}
	pendingReqs[id] = ch
	return ch
}

func takePendingRequestChan(id string) chan string {
	pendingReqsLk.Lock()
	defer pendingReqsLk.Unlock()
	if c, ok := pendingReqs[id]; ok {
		delete(pendingReqs, id)
		return c
	}
	return nil
}

func (r *request) run(e *env) error {
	r.Status = "pending"
	err := r.save(e)
	if err != nil {
		return fmt.Errorf("failed initial request save: %w", err)
	}

	ch := makePendingRequestChan(r.Id.String())
	// Emit the full request object so consumers can render the prompt
	// immediately without a follow-up Request/<id> round-trip. request_id
	// stays at the top level for backward-compat with anything that only
	// knows the old shape.
	go wltutil.BroadcastMsg("request", map[string]any{
		"request_id": r.Id.String(),
		"request":    r,
	})

	timeout := time.NewTimer(2 * time.Minute)
	defer timeout.Stop()

	var result string
	var ok bool

	select {
	case result, ok = <-ch:
		if !ok {
			r.Status = "rejected"
			r.save(e)
			return &apirouter.Error{Code: 4001, Message: "User rejected the request."}
		}
	case <-timeout.C:
		takePendingRequestChan(r.Id.String())
		r.Status = "timedout"
		r.save(e)
		return &apirouter.Error{Code: 4001, Message: "Request timed out."}
	}

	// reload req
	reloaded, err := psql.Get[request](e.sqlCtx, map[string]any{"Id": r.Id})
	if err == nil {
		*r = *reloaded
	}
	r.Status = result // just in case
	return nil
}

func (r *request) respond(e *env, resp string) error {
	r.Status = resp
	err := r.save(e)
	if err != nil {
		return err
	}

	ch := takePendingRequestChan(r.Id.String())
	if ch != nil {
		to := time.NewTimer(2 * time.Second)
		defer to.Stop()
		select {
		case ch <- resp:
			return nil
		case <-to.C:
			return errors.New("timed out while sending response")
		}
	}
	return nil
}

func requestTestReq(ctx context.Context) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	req := &request{
		Type: "test",
		Host: "www.example.com",
	}

	err := req.run(e)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func apiFetchRequest(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	id, err := xuid.ParsePrefix(in.Id, "req")
	if err != nil {
		return nil, err
	}

	return byPrimaryKey[request](e, id)
}

func apiListRequest(ctx *apirouter.Context) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	res, err := psql.Fetch[request](e.sqlCtx, nil, psql.Sort(psql.S("Created", "ASC")), psql.Limit(50))
	if err != nil {
		return nil, err
	}
	return res, nil
}

func requestDoApprove(ctx *apirouter.Context, in struct {
	Accounts []string
	Keys     []*wltsign.KeyDescription
	// Network is the user's chosen network ID for chain_switch
	// approvals. Ignored by other request types. Pair with
	// Accounts[0] which carries the chosen account ID.
	Network string
}) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	req := apirouter.GetObject[request](ctx, "Request")
	if req == nil {
		return nil, errors.New("request is required")
	}

	switch req.Type {
	case "connect":
		if len(in.Accounts) == 0 {
			return nil, errors.New("no accounts in approve connect, if there are no accounts it means the request was rejected")
		}
		// let's check if all those accounts are connected
		accts := make(map[string]*wltacct.Account)
		for _, acctId := range in.Accounts {
			a, err := wltacct.FindAccount(e, acctId)
			if err != nil {
				return nil, err
			}
			accts[a.Id.String()] = a
		}
		connAccts, _ := e.connectedAccounts(req.Host)
		for _, a := range connAccts {
			s := a.Account.String()
			if _, f := accts[s]; f {
				delete(accts, s)
			}
		}
		for _, acct := range accts {
			// connect it to req.Host
			conn := &connectedSite{
				Host:        req.Host,
				Account:     acct.Id,
				AccountInfo: acct,
			}
			err := conn.save(e)
			if err != nil {
				return nil, err
			}
			connAccts = append(connAccts, conn)
		}
		if len(accts) > 0 {
			// send event
			var list []string
			for _, c := range connAccts {
				list = append(list, c.AccountInfo.Address)
			}
			go wltutil.BroadcastMsg("js:accountsChanged", map[string]any{"accounts": list})
		}
	case "sign":
		if len(in.Keys) == 0 {
			return nil, errors.New("no keys in approve sign, keys are required to sign the transaction")
		}
		err := req.Transaction.SignAndSend(e, in.Keys)
		if err != nil {
			return nil, err
		}
	case "personal_sign":
		if len(in.Keys) == 0 {
			return nil, errors.New("no keys in approve sign, keys are required to sign the transaction")
		}
		signStr := req.Value.(string) // 0x...
		signBin, err := hex.DecodeString(signStr[2:])
		if err != nil {
			return nil, err
		}
		fullSignBin := append([]byte("\x19Ethereum Signed Message:\n"), []byte(strconv.Itoa(len(signBin)))...)
		fullSignBin = append(fullSignBin, signBin...)
		messageHash := cryptutil.Hash(fullSignBin, sha3.NewLegacyKeccak256)
		a, err := wltacct.FindAccount(e, *req.Account)
		if err != nil {
			return nil, fmt.Errorf("could not find account for signature: %w", err)
		}

		signOpt := &wltsign.Opts{
			Context: ctx,
			IL:      a.IL,
			Keys:    in.Keys,
		}
		sig, err := a.Sign(rand.Reader, messageHash, signOpt)
		if err != nil {
			return nil, fmt.Errorf("signature failed: %w", err)
		}
		str := "0x" + hex.EncodeToString(sig)
		req.Result = &str
	case "sign_typed_data":
		if len(in.Keys) == 0 {
			return nil, errors.New("keys are required to sign typed data")
		}
		typedDataStr, ok := req.Value.(string)
		if !ok {
			return nil, errors.New("invalid typed data in request")
		}
		td, err := ParseEIP712TypedData(typedDataStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EIP-712 data: %w", err)
		}
		digest, err := td.HashEIP712()
		if err != nil {
			return nil, fmt.Errorf("failed to compute EIP-712 hash: %w", err)
		}
		a, err := wltacct.FindAccount(e, *req.Account)
		if err != nil {
			return nil, fmt.Errorf("could not find account for signature: %w", err)
		}
		signOpt := &wltsign.Opts{
			Context: ctx,
			IL:      a.IL,
			Keys:    in.Keys,
		}
		sig, err := a.Sign(rand.Reader, digest, signOpt)
		if err != nil {
			return nil, fmt.Errorf("EIP-712 signature failed: %w", err)
		}
		str := "0x" + hex.EncodeToString(sig)
		req.Result = &str
	case "add_network":
		// wallet_addEthereumChain — pure add, no switch. Approval
		// acknowledged; the actual Save is done by the web3.go
		// caller. Kept distinct from chain_switch because the
		// intent is different (persist a new network without
		// activating it).
	case "chain_switch":
		// Unified network-switching approval. Two shapes:
		//
		//  • Pre-specified target (wallet_switchEthereumChain
		//    path): req.Value.TargetNetwork is set. Host only
		//    needs to return Accounts[0]; the target comes from
		//    the request, not the approve input.
		//
		//  • Picker (cross-family action method): req.Value.
		//    TargetNetwork nil, CandidateNetworks populated. Host
		//    returns both Network (picked id) and Accounts[0].
		//
		// We stash the full selection — including a marshalled
		// copy of the chosen Network when it's newly proposed and
		// not yet in the DB — into req.Result so the caller can
		// drive Save / SetCurrent / ensureConnected uniformly.
		v, err := decodeChainSwitchValue(req.Value)
		if err != nil {
			return nil, fmt.Errorf("chain_switch: malformed request value: %w", err)
		}
		if len(in.Accounts) != 1 {
			return nil, errors.New("chain_switch approval requires exactly one Account (the chosen account id)")
		}
		var chosen *wltnet.Network
		isNew := false
		if v.TargetNetwork != nil {
			chosen = v.TargetNetwork
			isNew = v.IsNewNetwork
		} else {
			if in.Network == "" {
				return nil, errors.New("chain_switch approval requires Network (the picker's chosen network id)")
			}
			for _, cand := range v.CandidateNetworks {
				if cand.Id != nil && cand.Id.String() == in.Network {
					chosen = cand
					break
				}
			}
			if chosen == nil {
				return nil, errors.New("chain_switch: chosen Network is not in CandidateNetworks")
			}
		}
		result := map[string]any{
			"network": chosen.Id.String(),
			"account": in.Accounts[0],
			"isNew":   isNew,
		}
		if isNew {
			// Pass the built Network object through so the
			// caller can Save it without re-parsing chain metadata.
			result["networkObj"] = chosen
		}
		req.Result = result
	case "watch_asset":
		// Approval acknowledged; the dApp is informed the asset was added to the watch list.
	case "mpurse_sign_message":
		if len(in.Keys) == 0 {
			return nil, errors.New("keys are required to sign")
		}
		msg, ok := req.Value.(string)
		if !ok {
			return nil, errors.New("invalid message in request")
		}
		a, err := wltacct.FindAccount(e, *req.Account)
		if err != nil {
			return nil, fmt.Errorf("could not find account: %w", err)
		}
		n, err := wltnet.CurrentNetwork(e)
		if err != nil {
			return nil, fmt.Errorf("no current network: %w", err)
		}
		prefix, ok := wltacct.BitcoinMessagePrefix(n.ChainId)
		if !ok {
			return nil, fmt.Errorf("no Bitcoin-family message prefix known for chain %q", n.ChainId)
		}
		signOpt := &wltsign.Opts{
			Context: ctx,
			IL:      a.IL,
			Keys:    in.Keys,
		}
		sig, err := a.SignBitcoinMessage(prefix, []byte(msg), signOpt)
		if err != nil {
			return nil, fmt.Errorf("mpurse message sign failed: %w", err)
		}
		b64 := base64.StdEncoding.EncodeToString(sig)
		req.Result = &b64
	case "mpurse_sign_transaction":
		if len(in.Keys) == 0 {
			return nil, errors.New("keys are required to sign")
		}
		txHex, ok := req.Value.(string)
		if !ok {
			return nil, errors.New("invalid tx in request")
		}
		rawTx, err := hex.DecodeString(txHex)
		if err != nil {
			return nil, fmt.Errorf("decode tx hex: %w", err)
		}
		a, err := wltacct.FindAccount(e, *req.Account)
		if err != nil {
			return nil, fmt.Errorf("could not find account: %w", err)
		}
		n, err := wltnet.CurrentNetwork(e)
		if err != nil {
			return nil, fmt.Errorf("no current network: %w", err)
		}
		signed, err := wlttx.SignRawBitcoinTx(&wlttx.SignContext{Env: e}, a, n, rawTx, in.Keys)
		if err != nil {
			return nil, fmt.Errorf("mpurse tx sign failed: %w", err)
		}
		out := hex.EncodeToString(signed)
		req.Result = &out
	case "solana_sign_message":
		if len(in.Keys) == 0 {
			return nil, errors.New("keys are required to sign")
		}
		msgB64, ok := req.Value.(string)
		if !ok {
			return nil, errors.New("invalid message in request")
		}
		msgBytes, err := base64.StdEncoding.DecodeString(msgB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode message: %w", err)
		}
		a, err := wltacct.FindAccount(e, *req.Account)
		if err != nil {
			return nil, fmt.Errorf("could not find account: %w", err)
		}
		// Legacy-wallet Ed25519 pubkey repair (see
		// wltwallet.EnsureEd25519Pubkey). Persists the corrected
		// Address so the dApp's next window.solana.publicKey read
		// returns the right value.
		_, _ = wltacct.EnsureEd25519PubkeyOnAccount(ctx, a, in.Keys)
		signOpt := &wltsign.Opts{
			Context: ctx,
			Keys:    in.Keys,
		}
		sig, err := a.Sign(nil, msgBytes, signOpt)
		if err != nil {
			return nil, fmt.Errorf("solana sign failed: %w", err)
		}
		req.Result = map[string]any{
			"signature": base58.Bitcoin.Encode(sig),
			"publicKey": a.Address,
		}
	case "solana_sign_transaction":
		if len(in.Keys) == 0 {
			return nil, errors.New("keys are required to sign")
		}
		txB64, ok := req.Value.(string)
		if !ok {
			return nil, errors.New("invalid transaction in request")
		}
		txBytes, err := base64.StdEncoding.DecodeString(txB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode transaction: %w", err)
		}
		a, err := wltacct.FindAccount(e, *req.Account)
		if err != nil {
			return nil, fmt.Errorf("could not find account: %w", err)
		}
		// Legacy-wallet Ed25519 pubkey repair. The CURRENT tx was
		// built by the dApp from the (wrong) pre-repair address, so
		// this signing attempt will still fail verification when
		// broadcast — but by the time the dApp refetches publicKey
		// and rebuilds, a.Address is correct.
		_, _ = wltacct.EnsureEd25519PubkeyOnAccount(ctx, a, in.Keys)
		// Solana transactions: the message to sign starts after the signature slots.
		// For a single-signer tx: compact-u16(1) + 64 bytes signature placeholder = 65 bytes header.
		// The message is everything after the signatures section.
		msgBytes, err := solanaExtractMessage(txBytes)
		if err != nil {
			return nil, err
		}
		signOpt := &wltsign.Opts{
			Context: ctx,
			Keys:    in.Keys,
		}
		sig, err := a.Sign(nil, msgBytes, signOpt)
		if err != nil {
			return nil, fmt.Errorf("solana sign failed: %w", err)
		}
		// Replace the first 64-byte signature slot with our signature
		signedTx := solanaInsertSignature(txBytes, sig)
		req.Result = map[string]any{
			"transaction": base64.StdEncoding.EncodeToString(signedTx),
		}
	case "solana_sign_send_transaction":
		if len(in.Keys) == 0 {
			return nil, errors.New("keys are required to sign")
		}
		txB64, ok := req.Value.(string)
		if !ok {
			return nil, errors.New("invalid transaction in request")
		}
		txBytes, err := base64.StdEncoding.DecodeString(txB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode transaction: %w", err)
		}
		a, err := wltacct.FindAccount(e, *req.Account)
		if err != nil {
			return nil, fmt.Errorf("could not find account: %w", err)
		}
		// Legacy-wallet Ed25519 pubkey repair. See notes on the
		// solana_sign_transaction case above.
		_, _ = wltacct.EnsureEd25519PubkeyOnAccount(ctx, a, in.Keys)
		msgBytes, err := solanaExtractMessage(txBytes)
		if err != nil {
			return nil, err
		}
		signOpt := &wltsign.Opts{
			Context: ctx,
			Keys:    in.Keys,
		}
		sig, err := a.Sign(nil, msgBytes, signOpt)
		if err != nil {
			return nil, fmt.Errorf("solana sign failed: %w", err)
		}
		signedTx := solanaInsertSignature(txBytes, sig)

		// Broadcast via Solana RPC
		env := wltintf.GetEnv(ctx)
		if env == nil {
			return nil, errors.New("failed to get env")
		}
		net, err := wltnet.CurrentNetwork(env)
		if err != nil {
			return nil, err
		}
		txBase58 := base58.Bitcoin.Encode(signedTx)
		result, err := net.DoRPC("sendTransaction", txBase58, map[string]any{"encoding": "base58"})
		if err != nil {
			return nil, fmt.Errorf("failed to send transaction: %w", err)
		}
		var txHash string
		if err := json.Unmarshal(result, &txHash); err != nil {
			return nil, fmt.Errorf("failed to parse transaction hash: %w", err)
		}
		wltintf.NotifyTxBroadcast(env)
		req.Result = map[string]any{
			"signature": txHash,
		}
	}

	return req, req.respond(e, "accepted")
}

func requestDoReject(ctx *apirouter.Context) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	req := apirouter.GetObject[request](ctx, "Request")
	if req == nil {
		return nil, errors.New("request is required")
	}

	return req, req.respond(e, "rejected")
}
