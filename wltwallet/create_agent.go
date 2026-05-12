package wltwallet

// Wallet:buildNewAgentBody — server-side helper that composes the body for
// the phplatform `Crypto/WalletSign:newAgent` POST.
//
// The Dart-side `WalletApi.createAgentWallet` does the user-authenticated
// HTTP call itself (so it can reuse the host's existing AtOnline bearer
// session without libwallet learning about auth tokens). All this endpoint
// does is fill in `mobile_spot_id` from the local Spot client, so the host
// app never has to read the spot id explicitly.
//
// Mirrors the split established by `ClawdWallet:pair`: libwallet owns the
// protocol-relevant fields, the app owns the user-facing transport.

import (
	"errors"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/pobj"
)

func init() {
	pobj.RegisterStatic("Wallet:buildNewAgentBody", apiBuildNewAgentBody)
}

// buildNewAgentBodyInput is the caller-supplied portion. The local Spot
// TargetId is filled in by libwallet.
type buildNewAgentBodyInput struct {
	Name        string         `json:"name"`
	AgentSpotID string         `json:"agent_spot_id"`
	Policy      map[string]any `json:"policy"`
}

// buildNewAgentBodyResult is the full body to POST to
// `Crypto/WalletSign:newAgent`. Keep field names matching the phplatform
// endpoint exactly — the Dart side passes this through without renaming.
type buildNewAgentBodyResult struct {
	Name         string         `json:"name"`
	AgentSpotID  string         `json:"agent_spot_id"`
	MobileSpotID string         `json:"mobile_spot_id"`
	Policy       map[string]any `json:"policy"`
}

func apiBuildNewAgentBody(ctx *apirouter.Context, in buildNewAgentBodyInput) (any, error) {
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	if in.AgentSpotID == "" {
		return nil, errors.New("agent_spot_id is required")
	}
	if in.Policy == nil {
		// Policy is required by the server but its shape is opaque to
		// libwallet — let phplatform reject an empty/invalid policy
		// with its own error so the wire contract stays single-sourced.
		return nil, errors.New("policy is required")
	}

	spot, err := envSpot(ctx)
	if err != nil {
		return nil, err
	}
	mobileSpotID := spot.TargetId()
	if mobileSpotID == "" {
		// Same retry guidance as the old Info:spotId — happens during
		// startup before the spot client comes online.
		return nil, errors.New("spot client is not online yet — retry shortly")
	}

	return &buildNewAgentBodyResult{
		Name:         in.Name,
		AgentSpotID:  in.AgentSpotID,
		MobileSpotID: mobileSpotID,
		Policy:       in.Policy,
	}, nil
}
