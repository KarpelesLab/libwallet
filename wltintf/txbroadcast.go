package wltintf

import "context"

// NotifyTxBroadcast is called after a transaction is successfully
// submitted to a network (EVM eth_sendRawTransaction, Solana
// sendTransaction, Bitcoin sendrawtransaction, etc.). The balance
// poller in wltbase subscribes to this event and triggers an
// immediate refresh so the UI sees the new balance within a second
// or two instead of waiting for the next 60 s tick.
//
// Safe to call with a nil Env (no-op). Never blocks.
func NotifyTxBroadcast(e Env) {
	if e == nil {
		return
	}
	h := e.Emitter()
	if h == nil {
		return
	}
	go h.Emit(context.Background(), "tx:broadcast", nil)
}
