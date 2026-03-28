package wltbase

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/libwallet/wlttx"
	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/typutil"
	"golang.org/x/crypto/sha3"
)

func init() {
	pobj.RegisterStatic("Web3:request", web3Req)

}

// Implement JSON-RPC methods from ethereum

type eip2255caveat struct {
	Type  string   `json:"type"`
	Value []string `json:"value"`
}

type eip2255perm struct {
	Id      string           `json:"id"`
	Invoker string           `json:"invoker"`
	Caveats []*eip2255caveat `json:"caveats"`
}

func web3Req(ctx context.Context, in struct {
	URL   string `json:"url"`
	Query struct {
		Method string `json:"method"`
		Params []any  `json:"params"`
	} `json:"query"`
}) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	// parse host from url
	u, err := url.Parse(in.URL)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, errors.New("url: host is missing")
	}
	// key is only scheme and host (Host includes the port in url if any was specified)
	key := (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()

	conn, _ := e.connectedAccounts(key)

	// fetch current network
	n, err := wltnet.CurrentNetwork(e)
	if err != nil {
		return nil, err
	}

	// See: https://docs.metamask.io/wallet/reference/wallet_addethereumchain/

	switch in.Query.Method {
	case "web3_clientVersion":
		return "libwallet/" + dateTag + "-" + gitTag, nil
	case "web3_sha3":
		if len(in.Query.Params) != 1 {
			return nil, errors.New("web3_sha3 expects exactly 1 param")
		}
		v := web3HexValue(in.Query.Params[0])
		if v == nil {
			return nil, errors.New("invalid parameter")
		}
		h := sha3.NewLegacyKeccak256()
		h.Write(v)
		res := h.Sum(nil)
		return "0x" + hex.EncodeToString(res), nil
	case "eth_requestAccounts":
		req := &request{
			Type: "connect",
			Host: key,
		}
		err := req.run(e)
		if err != nil {
			return nil, err
		}
		// approved
		conn = nil
		e.sql.Where(map[string]any{"Host": key}).Find(&conn)

		if len(conn) == 0 {
			return nil, nil
		}
		fallthrough
	case "eth_accounts":
		res := make([]string, 0, len(conn))
		for _, c := range conn {
			a, err := wltacct.FindAccount(e, c.Account.String())
			if err == nil {
				res = append(res, a.Address)
			}
		}
		return res, nil
	case "wallet_requestPermissions":
		// params: [{ eth_accounts: {} }],
		if len(in.Query.Params) != 1 {
			return nil, errors.New("wallet_requestPermissions requires one param")
		}
		// this is crappy, but we need to check if params[0] is indeed a map[string]any{"eth_accounts":map[string]any{}}
		pmap, ok := in.Query.Params[0].(map[string]any)
		if !ok {
			return nil, errors.New("wallet_requestPermissions requires param[0] to be an object")
		}
		var perms []string
		for k, _ := range pmap {
			switch k {
			case "eth_accounts":
				perms = append(perms, k)
			default:
				return nil, fmt.Errorf("unsupported permission %s", k)
			}
		}
		if len(perms) > 0 {
			// can only be eth_accounts
			req := &request{
				Type: "connect",
				Host: key,
			}
			err := req.run(e)
			if err != nil {
				return nil, err
			}
			// approved
			conn = nil
			e.sql.Where(map[string]any{"Host": key}).Find(&conn)

			if len(conn) == 0 {
				return nil, nil
			}
		}
		fallthrough
	case "wallet_getPermissions":
		res := make([]*eip2255perm, 0, len(conn))
		for _, c := range conn {
			a, err := wltacct.FindAccount(e, c.Account.String())
			if err == nil {
				tmp := &eip2255perm{
					Id:      c.Id.String(),
					Invoker: c.Host,
					Caveats: []*eip2255caveat{
						&eip2255caveat{
							Type:  "restrictReturnedAccounts",
							Value: []string{a.Address},
						},
					},
				}
				res = append(res, tmp)
			}
		}
		return res, nil
	case "personal_sign":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("personal_sign requires at least one parameter")
		}
		// params: [0xhex_msg, 0xoptional_sign_addr]
		if len(conn) == 0 {
			return nil, errors.New("no addr available")
		}
		addr := conn[0]
		if len(in.Query.Params) >= 2 {
			signAddr, ok := in.Query.Params[1].(string)
			if !ok {
				return nil, errors.New("invalid address parameter")
			}
			signAddr = strings.ToLower(signAddr)
			// addr in params[1], format is 0x...
			addr = nil
			for _, c := range conn {
				a, err := wltacct.FindAccount(e, c.Account.String())
				if err == nil {
					if strings.ToLower(a.Address) == signAddr {
						addr = c
						break
					}
				}
			}
			if addr == nil {
				return nil, errors.New("requested address not connected")
			}
		}
		val, ok := in.Query.Params[0].(string)
		if !ok {
			return nil, errors.New("invalid string for signature")
		}
		if !strings.HasPrefix(val, "0x") {
			return nil, errors.New("personal_sign: value must start with 0x")
		}
		valBin, err := hex.DecodeString(val[2:])
		if err != nil {
			return nil, fmt.Errorf("personal_sign: invalid value: %w", err)
		}
		a, err := wltacct.FindAccount(e, addr.Account.String())
		if err != nil {
			return nil, fmt.Errorf("failed to load account: %w", err)
		}

		req := &request{
			Type:    "personal_sign",
			Host:    key,
			Account: &a.Address,
			Value:   "0x" + hex.EncodeToString(valBin),
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		// approved
		return req.Result, nil
	case "eth_sendTransaction":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("eth_sendTransaction requires a transaction to sign")
		}
		tx, err := typutil.As[*wlttx.Transaction](in.Query.Params[0])
		if err != nil {
			return nil, err
		}
		tx.Type = "evm"
		err = tx.Validate(e)
		if err != nil {
			return nil, err
		}
		req := &request{
			Type:        "sign",
			Host:        key,
			Transaction: tx,
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		// approved
		return req.Transaction.Hash, nil
	case "wallet_addEthereumChain":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("wallet_addEthereumChain requires 1 parameter")
		}
		obj, err := typutil.As[*wltnet.AddEthereumChainParameter](in.Query.Params[0])
		if err != nil {
			return nil, err
		}
		err = obj.Validate()
		if err != nil {
			return nil, err
		}
		net := obj.AsNetwork()
		_, err = wltnet.NetworkById(e, net.Id)
		if err == nil {
			// already have this chain
			return nil, nil
		}

		req := &request{
			Type:  "add_network",
			Host:  key,
			Value: net,
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		// approved
		err = net.Save(e)
		if err != nil {
			return nil, err
		}
		return nil, nil
	case "wallet_switchEthereumChain":
		if len(in.Query.Params) < 1 {
			return nil, errors.New("wallet_switchEthereumChain requires 1 parameter")
		}
		s, err := typutil.As[string](in.Query.Params[0])
		if err != nil {
			return nil, err
		}
		// The chain ID as a 0x-prefixed hexadecimal string, per the eth_chainId method.
		bigV, ok := new(big.Int).SetString(s, 0)
		if !ok {
			return nil, fmt.Errorf("failed to parse network param %s", s)
		}
		id := wltnet.NetworkIdForTypeAndChainId("evm", bigV.Text(10))
		net, err := wltnet.NetworkById(e, id)
		if err != nil {
			// likely does not exist
			return nil, &apirouter.Error{Code: 4902, Message: "Unrecognized chain ID. Try adding the chain using wallet_addEthereumChain first."}
		}

		req := &request{
			Type:  "change_network",
			Host:  key,
			Value: net,
		}
		err = req.run(e)
		if err != nil {
			return nil, err
		}
		// approved
		err = net.SetCurrent(e)
		if err != nil {
			return nil, err
		}
		return nil, nil
	case "wallet_registerOnboarding":
		return false, nil
	default:
		// relay to current network
		return n.DoRPC(in.Query.Method, in.Query.Params...)
	}
}

func web3HexValue(in any) []byte {
	switch v := in.(type) {
	case string:
		// should start with 0x
		v = strings.TrimSpace(v)
		var ok bool
		v, ok = strings.CutPrefix(v, "0x")
		if !ok {
			return nil
		}
		r, err := hex.DecodeString(v)
		if err != nil {
			return nil
		}
		return r
	default:
		return nil
	}
}
