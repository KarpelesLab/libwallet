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
	RegisterProvider(&jupiterProvider{})
	RegisterProvider(&dflowProvider{})
	RegisterProvider(&oneInchProvider{})
}
