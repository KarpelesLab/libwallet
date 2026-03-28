package wltbase

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltsign"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/libwallet/wltutil"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
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
	Id          *xuid.XUID         `gorm:"primaryKey"`
	Type        string             // connect | sign | add_network | change_network | test
	Host        string             // URL of requesting site
	Status      string             // pending | accepted | rejected | timedout
	Account     *string            // account used for signature, if specified
	Transaction *wlttx.Transaction `json:",omitempty" gorm:"serializer:json"` // if Type=sign, contains the transaction to be signed
	Value       any                `json:",omitempty" gorm:"serializer:json"` // generic value
	Result      any                `json:",omitempty" gorm:"serializer:json"` // generic response
	Created     time.Time          `gorm:"autoCreateTime"`
	Updated     time.Time          `gorm:"autoUpdateTime"`
}

func (r *request) save(e *env) error {
	if r.Id == nil {
		// compute id
		r.Id = xuid.Must(xuid.NewRandom("req"))
	}
	return e.Save(r)
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
	// send event
	go wltutil.BroadcastMsg("request", map[string]any{"request_id": r.Id.String()})

	result, ok := <-ch
	if !ok {
		r.Status = "rejected"
		r.save(e)
		return &apirouter.Error{Code: 4001, Message: "User rejected the request."}
	}
	// reload req
	e.sql.First(r)    // will cause a re-fetch of the request
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

	var res []*request

	tx := e.sql
	tx = tx.Scopes(ctx.Paginate(50))
	tx = tx.Order("Created ASC")

	tx = tx.Find(&res)
	return res, tx.Error
}

func requestDoApprove(ctx *apirouter.Context, in struct {
	Accounts []string
	Keys     []*wltsign.KeyDescription
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
