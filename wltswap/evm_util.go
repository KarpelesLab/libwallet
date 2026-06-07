package wltswap

import (
	"context"
	"fmt"
	"time"

	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/libwallet/wltnet"
)

// fetchEVMNonce returns the pending-nonce for address on n via
// eth_getTransactionCount. Bounded by a short timeout so a stuck RPC
// node doesn't drag down the swap-build hot path; the caller can
// always retry. Lives here (not inside okx.go) so any future EVM
// path — a flip-back to another aggregator, or a non-swap EVM
// outbound — can reuse the helper without copy-paste.
func fetchEVMNonce(ctx context.Context, n *wltnet.Network, address string) (uint64, error) {
	rpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	v, err := ethrpc.ReadUint64(n.DoRPCCtx(rpcCtx, "eth_getTransactionCount", address, "pending"))
	if err != nil {
		return 0, fmt.Errorf("eth_getTransactionCount: %w", err)
	}
	return v, nil
}
