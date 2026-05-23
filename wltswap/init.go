package wltswap

import "github.com/KarpelesLab/pobj"

func init() {
	pobj.RegisterStatic("Swap:quote", swapQuote)
	pobj.RegisterStatic("Swap:quotes", swapQuotes)
	pobj.RegisterStatic("Swap:execute", swapExecute)
	pobj.RegisterStatic("Swap:buildApproval", swapBuildApproval)
	pobj.RegisterStatic("Swap:availability", swapAvailability)
	pobj.RegisterStatic("Swap:maxSpendable", swapMaxSpendable)

	// Providers register themselves — done eagerly at package init
	// so tests can override via RegisterProvider without needing a
	// dedicated setup step.
	//
	// OKX DEX (under `Crypto/Okx:*`) is the only routed provider
	// as of the licensing-driven migration. Jupiter / dFlow / 1inch
	// are intentionally left in the tree but unregistered — their
	// adapters keep working so the existing tests pass and the
	// flip-back is just two `//` removals here + restoring the
	// per-chain ordering in provider.go's providerOrderForChain.
	RegisterProvider(&okxSolanaProvider{})
	RegisterProvider(&okxEVMProvider{})
	// RegisterProvider(&jupiterProvider{})
	// RegisterProvider(&dflowProvider{})
	// RegisterProvider(&oneInchProvider{})
}
