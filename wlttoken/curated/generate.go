package curated

// Run at release time to refresh data/*.json from upstream feeds
// (Uniswap + Jupiter). The generator's source lives under ./gen/
// and is excluded from normal builds — it's `package main`.
//
//	go generate ./wlttoken/curated/...
//
// Does not touch overlay-*.json — those are hand-curated and merge
// over the generated base at load time. See curated.go:loadFromEmbed.

//go:generate go run ./gen
