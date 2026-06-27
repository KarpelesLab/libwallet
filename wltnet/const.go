package wltnet

// infuraKey is substituted into chain-registry RPC templates
// (${INFURA_API_KEY}) at runtime. Because it ships inside the client
// binary it is effectively public. AUDIT (I1): move Infura access behind
// a server-side proxy that injects the key, or replace it with a
// per-install / short-lived credential. Kept here unchanged to preserve
// runtime RPC resolution; rotating it requires backend coordination.
const (
	infuraKey = "f60d49a0d91c4f61afdaca8f961d2e20"
)
