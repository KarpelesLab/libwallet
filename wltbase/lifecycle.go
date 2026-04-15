package wltbase

import (
	"context"

	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pobj"
)

func init() {
	pobj.RegisterStatic("Lifecycle:update", lifecycleUpdate)
}

// lifecycleUpdate receives the host's current lifecycle status
// (`foreground` / `background` / `paused` / `resumed` / …). It echoes
// the accepted status and drives pause/resume of background work:
// the balance poller is paused in background, resumed on foreground.
func lifecycleUpdate(ctx context.Context, in struct {
	Status string `json:"status"`
}) (any, error) {
	if e, ok := wltintf.GetEnv(ctx).(*env); ok && e.poller != nil {
		switch in.Status {
		case "background", "paused":
			e.poller.pause()
		case "foreground", "resumed", "active", "":
			e.poller.resume()
		}
	}
	return map[string]any{"status": in.Status}, nil
}
