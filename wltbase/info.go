package wltbase

import (
	"context"
	"errors"
	"os"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltacct"
	"github.com/KarpelesLab/libwallet/wltlog"
	"github.com/KarpelesLab/libwallet/wltobj"
	"github.com/KarpelesLab/libwallet/wltutil"
	"github.com/KarpelesLab/libwallet/wltwallet"
	"github.com/KarpelesLab/pobj"
)

var (
	dateTag string
	gitTag  string
)

func init() {
	pobj.RegisterStatic("Info:ping", infoPing)
	pobj.RegisterStatic("Info:version", infoVersion)
	pobj.RegisterStatic("Info:paths", infoPaths)
	pobj.RegisterStatic("Info:first_run", infoFirstRun)
	pobj.RegisterStatic("Info:onboarding", infoOnboarding)
	pobj.RegisterStatic("Info:setWalletInfo", infoSetWalletInfo)
	pobj.RegisterStatic("Info:getWalletInfo", infoGetWalletInfo)

	// gitTag is populated by -ldflags in release builds (see the
	// Build workflow). An empty gitTag means this binary was built
	// from source without a release tag — usually a dev/CI build,
	// so default to "debug" logging. Release binaries default to
	// "info" so end users don't see per-RPC chatter but still get
	// the state-change lines that matter for support diagnosis.
	if gitTag == "" {
		wltlog.SetAutoDefault(wltlog.LevelDebug)
	} else {
		wltlog.SetAutoDefault(wltlog.LevelInfo)
	}

	// On Flutter+iOS the Go runtime's stderr doesn't reach the
	// Dart-side logger, so log.Printf output is invisible to the
	// host app no matter how verbose the level. Route every log
	// line through the broadcast channel instead — Dart already
	// subscribes to that stream for Web3 requests and online
	// status events. Host apps print the "log" event payload
	// with developer.log / print; release builds can silence it
	// by setting LogLevel="off". See dart/lib/src/client/*.
	wltlog.SetSink(func(level wltlog.Level, line string) {
		wltutil.BroadcastMsg("log", map[string]any{
			"level": level.String(),
			"msg":   line,
		})
	})
}

// infoSetWalletInfo registers the host wallet's identity block.
// Currently sends ClientID as the Sec-ClientId HTTP header on every
// Crypto/WalletSign:* call; Name + Version are stored for future use;
// LogLevel controls wltlog verbosity. Pass zero-valued fields to clear.
func infoSetWalletInfo(in struct {
	ClientID string `json:"ClientId"`
	Name     string `json:"Name"`
	Version  string `json:"Version"`
	LogLevel string `json:"LogLevel"`
}) (any, error) {
	wltwallet.SetWalletInfo(wltwallet.WalletInfo{
		ClientID: in.ClientID,
		Name:     in.Name,
		Version:  in.Version,
		LogLevel: in.LogLevel,
	})
	return infoGetWalletInfoValue(), nil
}

func infoGetWalletInfo() (any, error) {
	return infoGetWalletInfoValue(), nil
}

// infoGetWalletInfoValue returns the stored WalletInfo plus the
// effective log level (what libwallet is actually using right now),
// so hosts can tell whether an empty LogLevel resolved to "debug" or
// "info" without having to recompute the logic themselves.
func infoGetWalletInfoValue() map[string]any {
	info := wltwallet.GetWalletInfo()
	return map[string]any{
		"clientId":           info.ClientID,
		"name":               info.Name,
		"version":            info.Version,
		"logLevel":           info.LogLevel,
		"effectiveLogLevel":  wltlog.GetLevel().String(),
	}
}

func infoPing() (any, error) {
	return "pong", nil
}

func infoVersion() (any, error) {
	return map[string]any{
		"dateTag": dateTag,
		"gitTag":  gitTag,
	}, nil
}

func infoPaths(ctx context.Context) (any, error) {
	res := make(map[string]any)

	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	if v, err := os.UserCacheDir(); err == nil {
		res["UserCacheDir"] = v
	}
	if v, err := os.UserConfigDir(); err == nil {
		res["UserConfigDir"] = v
	}
	if v, err := os.UserHomeDir(); err == nil {
		res["UserHomeDir"] = v
	}
	res["TempDir"] = os.TempDir()
	res["DataDir"] = e.dataDir
	res["Environ"] = os.Environ()

	return res, nil
}

func infoFirstRun(ctx context.Context) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	v, err := e.ConfigGet("first_run")
	if err != nil {
		return nil, err
	}
	t := &wltobj.TimeId{}
	err = t.UnmarshalBinary(v)
	return t, err
}

func infoOnboarding(ctx context.Context) (any, error) {
	e := apirouter.GetObject[env](ctx, "@env")
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	acct := wltacct.HasAccount(e)
	wallet := wltwallet.HasWallet(e)

	res := map[string]any{
		"has_account": acct,
		"has_wallet":  wallet,
	}
	return res, nil
}
