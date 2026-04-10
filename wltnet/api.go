package wltnet

import (
	"errors"
	"fmt"
	"strings"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/ethrpc/chains"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

func init() {
	pobj.RegisterActions[Network]("Network",
		&pobj.ObjectActions{
			Fetch:  pobj.Static(apiFetchNetwork),
			List:   pobj.Static(apiListNetwork),
			Create: pobj.Static(apiCreateNetwork),
		},
	)
	pobj.RegisterStatic("Network:setCurrent", networkSetCurrent)
	pobj.RegisterStatic("Network:testRPC", networkTestRPC)
}

func NetworkById(e wltintf.Env, id *xuid.XUID) (*Network, error) {
	if id.Prefix != "net" {
		return nil, fmt.Errorf("invalid key for network: %s", id.Prefix)
	}
	if n := networkFromCache(id); n != nil {
		return n, nil
	}
	return wltintf.ByPrimaryKey[Network](e, id)
}

func CurrentNetworkId(e wltintf.Env) (string, error) {
	return e.GetCurrent("network")
}

func evmNetwork(e wltintf.Env, chainId string, prio int, testNet bool) (*Network, error) {
	// search in db
	n, err := psql.Get[Network](e, map[string]any{"Type": "evm", "ChainId": chainId})
	if err == nil {
		return n, nil
	}
	n = &Network{Type: "evm", ChainId: chainId, Priority: prio, TestNet: testNet}
	err = n.check()
	if err != nil {
		return nil, err
	}
	return n, n.Save(e)
}

func bitcoinNetwork(e wltintf.Env, chainId string, prio int, testNet bool) (*Network, error) {
	// search in db
	n, err := psql.Get[Network](e, map[string]any{"Type": "bitcoin", "ChainId": chainId})
	if err == nil {
		return n, nil
	}
	n = &Network{Type: "bitcoin", ChainId: chainId, Priority: prio, TestNet: testNet}
	err = n.check()
	if err != nil {
		return nil, err
	}
	return n, n.Save(e)
}

func solanaNetwork(e wltintf.Env, chainId string, prio int, testNet bool) (*Network, error) {
	n, err := psql.Get[Network](e, map[string]any{"Type": "solana", "ChainId": chainId})
	if err == nil {
		return n, nil
	}
	n = &Network{Type: "solana", ChainId: chainId, Priority: prio, TestNet: testNet}
	err = n.check()
	if err != nil {
		return nil, err
	}
	return n, n.Save(e)
}

func CurrentNetwork(e wltintf.Env) (*Network, error) {
	id, err := CurrentNetworkId(e)
	if err != nil {
		return evmNetwork(e, "1", 100, false)
	}

	xid, err := xuid.Parse(id)
	if err != nil {
		return nil, err
	}
	return NetworkById(e, xid)
}

func apiFetchNetwork(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	if in.Id == "@" {
		// get current network
		return CurrentNetwork(e)
	}
	id := strings.Split(in.Id, ".")
	if len(id) != 2 {
		id, err := xuid.Parse(in.Id)
		if err != nil {
			return nil, err
		}
		return NetworkById(e, id)
	}

	res := &Network{Type: id[0], ChainId: id[1]}
	return res, nil
}

func (n *Network) ApiDelete(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	_, err := psql.ForceDelete[Network](e, map[string]any{"Id": n.Id})
	return err
}

func (n *Network) ApiUpdate(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	updated := false

	if v, ok := apirouter.GetParam[string](ctx, "Name"); ok {
		n.Name = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "RPC"); ok {
		n.RPC = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "CurrencySymbol"); ok {
		n.CurrencySymbol = v
		updated = true
	}
	if v, ok := apirouter.GetParam[bool](ctx, "TestNet"); ok {
		n.TestNet = v
		updated = true
	}
	if v, ok := apirouter.GetParam[int](ctx, "Priority"); ok {
		n.Priority = v
		updated = true
	}

	if !updated {
		return nil
	}
	n.check()
	return n.Save(e)
}

type netInfo struct {
	chainId  string
	priority int
	testNet  bool
}

func MakeDefaultNetworks(e wltintf.Env) error {
	netList := []netInfo{
		netInfo{"1", 100, false},
		netInfo{"137", 50, false},
		netInfo{"56", 10, false},
		netInfo{"11155111", -10, true},
		netInfo{"80002", -50, true},
	}
	for _, s := range netList {
		evmNetwork(e, s.chainId, s.priority, s.testNet)
	}

	netList = []netInfo{
		netInfo{"bitcoin", 99, false},
		netInfo{"bitcoin-cash", 98, false},
		netInfo{"litecoin", 49, false},
		netInfo{"dogecoin", 40, false},
	}
	for _, s := range netList {
		bitcoinNetwork(e, s.chainId, s.priority, s.testNet)
	}

	solanaNetwork(e, "mainnet", 97, false)

	return nil
}

func apiListNetwork(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	return wltintf.ListHelper[Network](ctx, "Priority DESC", "TestNet")
}

func networkSetCurrent(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	nt := apirouter.GetObject[Network](ctx, "Network")
	if nt == nil {
		return nil, errors.New("network required")
	}

	err := nt.SetCurrent(e)
	return nt, err
}

func apiCreateNetwork(ctx *apirouter.Context, n *Network) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	// for ce create
	n.Id = nil

	err := n.check()
	if err != nil {
		return nil, err
	}

	return n, n.Save(e)
}

func networkTestRPC(ctx *apirouter.Context, in struct{ URL string }) (any, error) {
	u := in.URL
	if u == "" {
		return nil, errors.New("invalid url")
	}

	// rpc
	rpc := ethrpc.New(u)
	id, err := ethrpc.ReadUint64(rpc.Do("net_version"))
	if err != nil {
		return nil, err
	}

	res := map[string]any{
		"RPC":     u,
		"ChainId": id,
	}

	// get chain info
	info := chains.Get(id)
	if info == nil {
		return res, nil
	}
	res["EVM_Info"] = info
	res["Name"] = info.Name
	res["CurrencySymbol"] = info.NativeCurrency.Symbol
	return res, nil
}
