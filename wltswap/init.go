package wltswap

import "github.com/KarpelesLab/pobj"

func init() {
	pobj.RegisterStatic("Swap:quote", swapQuote)
	pobj.RegisterStatic("Swap:quotes", swapQuotes)
	pobj.RegisterStatic("Swap:execute", swapExecute)
	pobj.RegisterStatic("Swap:buildApproval", swapBuildApproval)
	pobj.RegisterStatic("Swap:availability", swapAvailability)
	pobj.RegisterStatic("Swap:countryAvailability", swapCountryAvailability)
	pobj.RegisterStatic("Swap:maxSpendable", swapMaxSpendable)
	pobj.RegisterStatic("Swap:orderStatus", swapOrderStatus)

	// OKX DEX is the only routed swap provider. Both adapters
	// register themselves at package init so test doubles can
	// substitute via RegisterProvider without a separate setup step.
	RegisterProvider(&okxSolanaProvider{})
	RegisterProvider(&okxEVMProvider{})
}
