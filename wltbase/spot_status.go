package wltbase

import (
	"context"
	"errors"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pobj"
)

func init() {
	pobj.RegisterStatic("Spot:status", spotStatus)
}

// spotStatus exposes the current Spot client state to hosts. Lets
// callers positively poll connectivity instead of relying on the
// edge-triggered "online_status" broadcast (which they may have
// missed if Spot came online before the host subscribed). Used to
// diagnose device-transfer pair hangs: if Online is false, the
// source can't be reached and the pairing QR will never receive
// the receiver's request.
//
// Returns:
//
//	online             — true iff at least one Spot connection is past
//	                     the handshake (matches what waitOnlineSpot guards).
//	target_id          — local node's "k.<base64url>" id. Stable across
//	                     restarts because it's derived from the keys.
//	connections.total  — number of attempted Spot broker connections.
//	connections.online — subset that finished handshaking.
//
// Returns an error when the environment isn't initialised yet.
func spotStatus(ctx context.Context, _ struct{}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("env not available")
	}
	spot := e.Spot()
	if spot == nil {
		return nil, errors.New("spot client not initialised")
	}
	total, online := spot.ConnectionCount()
	return map[string]any{
		"online":    online > 0,
		"target_id": spot.TargetId(),
		"connections": map[string]any{
			"total":  total,
			"online": online,
		},
	}, nil
}
