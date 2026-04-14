package wltwc

import (
	"errors"
	"sync"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/pobj"
	"github.com/portablesql/psql"
)

// One Manager per env. The env interface doesn't expose a place to attach
// arbitrary objects, so we keep a process-wide map keyed by env identity.
var (
	managers   = make(map[wltintf.Env]*Manager)
	managersMu sync.Mutex
)

func managerFor(e wltintf.Env) *Manager {
	managersMu.Lock()
	defer managersMu.Unlock()
	m, ok := managers[e]
	if !ok {
		m = NewManager(e)
		managers[e] = m
	}
	return m
}

func init() {
	pobj.RegisterStatic("WalletConnect:start", wcStart)
	pobj.RegisterStatic("WalletConnect:stop", wcStop)
	pobj.RegisterStatic("WalletConnect:pair", wcPair)
	pobj.RegisterStatic("WalletConnect:sessions", wcListSessions)
	pobj.RegisterStatic("WalletConnect:approveSession", wcApproveSession)
	pobj.RegisterStatic("WalletConnect:rejectSession", wcRejectSession)
	pobj.RegisterStatic("WalletConnect:respond", wcRespond)
	pobj.RegisterStatic("WalletConnect:respondError", wcRespondError)
	pobj.RegisterStatic("WalletConnect:emitEvent", wcEmitEvent)
	pobj.RegisterStatic("WalletConnect:disconnect", wcDisconnect)
}

// InitEnv wires a Manager into the env. Consumers still need to call
// WalletConnect:start with their relay URL + projectId before inbound
// sessions start flowing.
func InitEnv(e wltintf.Env) {
	_ = managerFor(e)
	// Ensure table exists.
	_ = psql.Replace(e, &wcSession{}) // triggers schema creation; value is no-op
}

// wcStart opens the relay connection.
func wcStart(ctx *apirouter.Context, in struct {
	RelayURL  string
	ProjectID string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("no env")
	}
	if in.RelayURL == "" {
		in.RelayURL = "wss://relay.walletconnect.com"
	}
	if in.ProjectID == "" {
		return nil, errors.New("ProjectID is required")
	}
	return nil, managerFor(e).Start(in.RelayURL, in.ProjectID)
}

func wcStop(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("no env")
	}
	managerFor(e).Stop()
	return nil, nil
}

// wcPair accepts a wc:… URI and starts the pairing flow.
func wcPair(ctx *apirouter.Context, in struct {
	URI string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("no env")
	}
	topic, err := managerFor(e).StartPairing(in.URI)
	if err != nil {
		return nil, err
	}
	return map[string]any{"pairingTopic": topic}, nil
}

func wcListSessions(ctx *apirouter.Context) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("no env")
	}
	return allNonClosedSessions(e)
}

func wcApproveSession(ctx *apirouter.Context, in struct {
	PairingTopic string
	Accounts     []string
	Methods      []string
	Events       []string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("no env")
	}
	return nil, managerFor(e).ApproveProposal(in.PairingTopic, in.Accounts, in.Methods, in.Events)
}

func wcRejectSession(ctx *apirouter.Context, in struct {
	PairingTopic string
	Code         int
	Message      string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("no env")
	}
	return nil, managerFor(e).RejectProposal(in.PairingTopic, in.Code, in.Message)
}

func wcRespond(ctx *apirouter.Context, in struct {
	Topic  string
	ID     int64
	Result any
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("no env")
	}
	return nil, managerFor(e).RespondSession(in.Topic, in.ID, in.Result)
}

func wcRespondError(ctx *apirouter.Context, in struct {
	Topic   string
	ID      int64
	Code    int
	Message string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("no env")
	}
	return nil, managerFor(e).RespondSessionError(in.Topic, in.ID, in.Code, in.Message)
}

func wcEmitEvent(ctx *apirouter.Context, in struct {
	Topic   string
	Name    string
	Data    any
	ChainID string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("no env")
	}
	return nil, managerFor(e).EmitSessionEvent(in.Topic, in.Name, in.Data, in.ChainID)
}

func wcDisconnect(ctx *apirouter.Context, in struct {
	Topic string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("no env")
	}
	return nil, managerFor(e).Disconnect(in.Topic)
}
