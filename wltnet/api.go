package wltnet

import (
	"context"
	"encoding/json"
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

// SolanaBroadcastNetwork returns the Solana network to use when broadcasting
// a Solana transaction. If CurrentNetwork already points at a Solana cluster
// (e.g. the user has switched to devnet for testing), that selection is
// preserved. Otherwise we fall back to the default Solana mainnet entry —
// MakeDefaultNetworks always seeds one. Without this fallback,
// Account:signAndSendTransaction would route Solana txs to whatever the user
// happens to be looking at in the wallet UI — typically an EVM RPC, which
// rejects them with "method sendTransaction does not exist".
func SolanaBroadcastNetwork(e wltintf.Env) (*Network, error) {
	if cur, err := CurrentNetwork(e); err == nil && cur != nil && cur.Type == "solana" {
		return cur, nil
	}
	return solanaNetwork(e, "mainnet", 97, false)
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
	if err == nil {
		// Fire event for subscribers in wltbase (balance poller,
		// tx-history backfill). Async — doesn't block the API call.
		e.Emitter().Emit(context.Background(), "network:current_changed", nt.Id.String())
	}
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

// networkTestRPC pings an RPC endpoint and returns a structured health
// snapshot. Type is required — use "evm", "solana", or "bitcoin"
// depending on which kind of node the URL points at. Response shape
// depends on [Type]:
//
//   evm     : {RPC, Type, ChainId, Name?, CurrencySymbol?, EVM_Info?}
//   solana  : {RPC, Type, SolanaVersion, SolanaCluster}
//              cluster ∈ {"mainnet-beta", "devnet", "testnet", "unknown"}
//   bitcoin : {RPC, Type, Chain, Blocks}
func networkTestRPC(ctx *apirouter.Context, in struct {
	URL  string
	Type string
}) (any, error) {
	u := in.URL
	if u == "" {
		return nil, errors.New("invalid url")
	}
	typ := in.Type
	if typ == "" {
		// Back-compat: the endpoint used to accept only EVM URLs.
		typ = "evm"
	}

	switch typ {
	case "evm":
		return testRPCEVM(u)
	case "solana":
		return testRPCSolana(u)
	case "bitcoin":
		return testRPCBitcoin(u)
	default:
		return nil, fmt.Errorf("unsupported Type %q (want evm | solana | bitcoin)", typ)
	}
}

func testRPCEVM(u string) (any, error) {
	rpc := ethrpc.New(u)
	id, err := ethrpc.ReadUint64(rpc.Do("net_version"))
	if err != nil {
		return nil, err
	}
	res := map[string]any{
		"RPC":     u,
		"Type":    "evm",
		"ChainId": id,
	}
	if info := chains.Get(id); info != nil {
		res["EVM_Info"] = info
		res["Name"] = info.Name
		res["CurrencySymbol"] = info.NativeCurrency.Symbol
	}
	return res, nil
}

// solanaClusters maps genesis-hash (base58) to the named Solana cluster.
// These hashes are immutable per-cluster. When getGenesisHash returns
// something else, report "unknown" rather than guessing.
var solanaClusters = map[string]string{
	"5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp1T3LwG9BWb8e": "mainnet-beta",
	"EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG": "devnet",
	"4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY": "testnet",
}

func testRPCSolana(u string) (any, error) {
	rpc := ethrpc.New(u)
	// getVersion → {"solana-core": "1.17.x", "feature-set": 12345}
	raw, err := rpc.Do("getVersion")
	if err != nil {
		return nil, fmt.Errorf("getVersion: %w", err)
	}
	var ver struct {
		Core       string `json:"solana-core"`
		FeatureSet uint64 `json:"feature-set"`
	}
	if err := json.Unmarshal(raw, &ver); err != nil {
		return nil, fmt.Errorf("decode getVersion: %w", err)
	}

	// Identify the cluster via the genesis hash.
	genesis, err := ethrpc.ReadString(rpc.Do("getGenesisHash"))
	cluster := "unknown"
	if err == nil {
		if name, ok := solanaClusters[genesis]; ok {
			cluster = name
		}
	}
	return map[string]any{
		"RPC":           u,
		"Type":          "solana",
		"SolanaVersion": ver.Core,
		"SolanaCluster": cluster,
	}, nil
}

func testRPCBitcoin(u string) (any, error) {
	rpc := ethrpc.New(u)
	// getblockchaininfo works against modchain proxies, native bitcoind,
	// and any fork (litecoind, dogecoind, monacoin-core, bitcoin-abc).
	raw, err := rpc.Do("getblockchaininfo")
	if err != nil {
		return nil, fmt.Errorf("getblockchaininfo: %w", err)
	}
	var info struct {
		Chain  string `json:"chain"`  // "main" / "test" / "regtest" / "signet" (also "monacoin" / etc. on forks)
		Blocks uint64 `json:"blocks"`
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("decode getblockchaininfo: %w", err)
	}
	return map[string]any{
		"RPC":    u,
		"Type":   "bitcoin",
		"Chain":  info.Chain,
		"Blocks": info.Blocks,
	}, nil
}
