package wltbase

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/libwallet/wltutil"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
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
	if ch == nil {
		// The pending channel was already consumed (the request
		// timed out, was rejected, or a previous respond already
		// delivered). Surface this instead of silently succeeding —
		// a caller that just performed signing/broadcast side
		// effects must know the waiter is gone.
		return errors.New("request is no longer awaiting a response")
	}
	to := time.NewTimer(2 * time.Second)
	defer to.Stop()
	select {
	case ch <- resp:
		return nil
	case <-to.C:
		return errors.New("timed out while sending response")
	}
}

// claim performs an atomic compare-and-set that moves a pending
// request into an in-progress ("processing") state before any
// signing / broadcast side effects run. It reloads the authoritative
// row so an already-terminal request (rejected / timedout / accepted)
// can't be approved a second time, and requires the in-memory pending
// channel to still exist so a timed-out request whose waiter already
// gave up is rejected too. The pendingReqsLk mutex makes the
// reload-check-write sequence atomic within the process.
func (r *request) claim(e *env) error {
	pendingReqsLk.Lock()
	defer pendingReqsLk.Unlock()

	id := r.Id.String()
	if _, ok := pendingReqs[id]; !ok {
		return errors.New("request is no longer awaiting a response")
	}
	reloaded, err := psql.Get[request](e.sqlCtx, map[string]any{"Id": r.Id})
	if err != nil {
		return fmt.Errorf("failed to reload request: %w", err)
	}
	if reloaded.Status != "pending" {
		return fmt.Errorf("request is not pending (status %q)", reloaded.Status)
	}
	// Compare-and-set: flip to the in-progress state and persist it
	// before returning, so any later approve/reject of the same row
	// observes a non-pending status and is rejected.
	reloaded.Status = "processing"
	if err := reloaded.save(e); err != nil {
		return fmt.Errorf("failed to claim request: %w", err)
	}
	// Adopt the authoritative row for the handlers but keep the
	// working copy logically pending; respond() sets the terminal
	// status, releaseClaim() rolls back on failure.
	*r = *reloaded
	r.Status = "pending"
	return nil
}

// releaseClaim finalizes a claim. On success the terminal status was
// already set by respond(); on failure the in-progress flag is rolled
// back to "pending" so a legitimate retry can run.
func (r *request) releaseClaim(e *env, succeeded bool) {
	if succeeded {
		return
	}
	pendingReqsLk.Lock()
	defer pendingReqsLk.Unlock()
	reloaded, err := psql.Get[request](e.sqlCtx, map[string]any{"Id": r.Id})
	if err == nil && reloaded.Status == "processing" {
		reloaded.Status = "pending"
		reloaded.save(e)
	}
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

	// Idempotency / state guard: atomically claim the pending row so
	// the signing/broadcast side effects below run at most once and a
	// timed-out or already-handled request can't be approved.
	if err := req.claim(e); err != nil {
		return nil, err
	}
	succeeded := false
	defer func() { req.releaseClaim(e, succeeded) }()

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
	case "transaction_sign":
		// Unified tx-signing approval. Method-dispatched against
		// the rich TransactionSignValue payload the emitter built
		// — same chain coverage as the old per-method cases
		// (sign / solana_sign_transaction /
		// solana_sign_send_transaction / mpurse_sign_transaction)
		// but exposed as a single event type to the host.
		if err := approveTransactionSign(ctx, e, req, in.Keys); err != nil {
			return nil, err
		}
	case "message_sign":
		// Unified arbitrary-data signing approval (personal_sign,
		// eth_signTypedData*, solana_signMessage,
		// mpurse_signMessage). Method dispatch from the rich
		// MessageSignValue payload.
		if err := approveMessageSign(ctx, e, req, in.Keys); err != nil {
			return nil, err
		}
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
	}

	if err := req.respond(e, "accepted"); err != nil {
		return nil, err
	}
	succeeded = true
	return req, nil
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

	// Same state guard as approve: only a still-pending request can
	// be rejected, and the transition is atomic.
	if err := req.claim(e); err != nil {
		return nil, err
	}
	if err := req.respond(e, "rejected"); err != nil {
		req.releaseClaim(e, false)
		return nil, err
	}
	return req, nil
}
