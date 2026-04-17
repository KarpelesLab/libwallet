package wltswap

import "github.com/KarpelesLab/pobj"

func init() {
	pobj.RegisterStatic("Swap:quote", swapQuote)
	pobj.RegisterStatic("Swap:execute", swapExecute)

	// Providers register themselves — done eagerly at package init
	// so tests can override via RegisterProvider without needing a
	// dedicated setup step.
	RegisterProvider(&jupiterProvider{})
	RegisterProvider(&dflowProvider{})
	RegisterProvider(&oneInchProvider{})
}
