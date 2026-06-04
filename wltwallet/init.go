package wltwallet

import (
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/spotproto"
)

func InitEnv(e wltintf.Env) {
	// Install the single, permanent Spot handler that receives every
	// device-transfer pair request. Sessions live in transferRegistry
	// keyed by sid; the handler claims one out of the registry per
	// incoming request. Endpoint is the bare "transfer" prefix
	// because spotlib's dispatcher only matches the first path
	// segment after the recipient id — a deeper "transfer/<sid>"
	// key never resolves, and the receiver hangs the full
	// transferQueryTimeout before giving up.
	if spot := e.Spot(); spot != nil {
		spot.SetHandler(transferSpotPrefix, func(msg *spotproto.Message) ([]byte, error) {
			return transferHandle(e, msg)
		})
	}
}
