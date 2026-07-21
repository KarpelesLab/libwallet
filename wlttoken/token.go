package wlttoken

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/KarpelesLab/apirouter"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
	"github.com/KarpelesLab/outscript"
	"github.com/KarpelesLab/pobj"
	"github.com/KarpelesLab/xuid"
	"github.com/portablesql/psql"
)

// Bounds applied to untrusted token metadata (on-chain symbol / name /
// decimals, plus operator-supplied overrides). Token symbols and names
// originate from contract calls or RPC metadata an attacker controls, so
// they are sanitised and capped to defeat display-spoofing (control
// chars, bidi overrides, homographs, unbounded length) and decimals are
// bounded because they feed amount scaling.
const (
	maxTokenSymbolLen = 32
	maxTokenNameLen   = 128
	maxTokenDecimals  = 36
)

// sanitizeTokenText strips control and bidirectional/zero-width
// formatting characters from untrusted token metadata and caps the
// result to maxLen runes. This prevents token-impersonation and
// terminal/display corruption from on-chain symbol/name fields
// (e.g. a U+202E RIGHT-TO-LEFT OVERRIDE that visually reverses text,
// or homograph padding hidden behind zero-width joiners).
func sanitizeTokenText(s string, maxLen int) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r == unicode.ReplacementChar:
			// dropped: invalid UTF-8 sequence
		case unicode.IsControl(r):
			// dropped: C0/C1 control characters
		case isBidiOrInvisible(r):
			// dropped: bidi overrides / zero-width / BOM
		default:
			out = append(out, r)
			if len(out) >= maxLen {
				return strings.TrimSpace(string(out))
			}
		}
	}
	return strings.TrimSpace(string(out))
}

// isBidiOrInvisible reports whether r is a bidirectional formatting
// control or an invisible/zero-width character commonly abused to spoof
// or corrupt displayed token names.
func isBidiOrInvisible(r rune) bool {
	switch {
	case r >= '\u202A' && r <= '\u202E': // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= '\u2066' && r <= '\u2069': // LRI, RLI, FSI, PDI
		return true
	case r >= '\u200B' && r <= '\u200F': // ZWSP, ZWNJ, ZWJ, LRM, RLM
		return true
	case r == '\u061C': // Arabic letter mark
		return true
	case r == '\uFEFF': // zero-width no-break space / BOM
		return true
	}
	return false
}

type token struct {
	TableName psql.Name  `sql:"Token"`
	Id        *xuid.XUID `sql:",key=PRIMARY"`
	Name      string     `sql:",type=VARCHAR,size=255"`
	Symbol    string     `sql:",type=VARCHAR,size=255"`
	Address   string     `sql:",type=VARCHAR,size=255"`
	Decimals  int        `sql:",type=INT"`
	Type      string     `sql:",type=VARCHAR,size=255"` // erc20, nft, spl-token, spl-token-2022
	Network   *xuid.XUID `sql:",type=VARCHAR,size=255"`
	Logo      string     `sql:",type=TEXT"`
	Memo      string     `sql:",type=TEXT"`
	Created   time.Time  `sql:",type=DATETIME"`
	Updated   time.Time  `sql:",type=DATETIME"`
}

func init() {
	pobj.RegisterActions[token]("Token",
		&pobj.ObjectActions{
			Fetch:  pobj.Static(apiFetchToken),
			List:   pobj.Static(apiListToken),
			Create: pobj.Static(apiCreateToken),
		},
	)
}

func (t *token) validate(e wltintf.Env) error {
	if t.Network == nil {
		return errors.New("Network is required")
	}
	if t.Address == "" {
		return errors.New("Address is required")
	}

	net, err := wltnet.NetworkById(e, t.Network)
	if err != nil {
		return fmt.Errorf("invalid network: %w", err)
	}

	switch net.Type {
	case "evm":
		addr, err := outscript.ParseEvmAddress(t.Address)
		if err != nil {
			return fmt.Errorf("invalid EVM address: %w", err)
		}
		t.Address, err = addr.Address()
		if err != nil {
			return fmt.Errorf("failed to normalize EVM address: %w", err)
		}
		if t.Type == "" {
			t.Type = "erc20"
		}
	case "solana":
		decoded, err := base58.Bitcoin.Decode(t.Address)
		if err != nil {
			return fmt.Errorf("invalid Solana address: %w", err)
		}
		if len(decoded) != 32 {
			return errors.New("invalid Solana address: must be 32 bytes")
		}
		t.Address = base58.Bitcoin.Encode(decoded)
		if t.Type == "" {
			t.Type = "spl-token"
		}
	default:
		return fmt.Errorf("tokens are not supported on %s networks", net.Type)
	}

	// Sanitise display metadata — Symbol/Name may originate from
	// untrusted on-chain sources (discovery, swap EnsureToken) and are
	// otherwise persisted verbatim.
	t.Symbol = sanitizeTokenText(t.Symbol, maxTokenSymbolLen)
	t.Name = sanitizeTokenText(t.Name, maxTokenNameLen)

	if t.Decimals < 0 || t.Decimals > maxTokenDecimals {
		return fmt.Errorf("Decimals must be between 0 and %d", maxTokenDecimals)
	}

	return nil
}

func (t *token) save(e wltintf.Env) error {
	now := time.Now()
	if t.Created.IsZero() {
		t.Created = now
	}
	t.Updated = now
	return psql.Replace(e, t)
}

func TokenById(e wltintf.Env, id *xuid.XUID) (*token, error) {
	if id.Prefix != "tok" {
		return nil, fmt.Errorf("invalid key for token: %s", id.Prefix)
	}
	return wltintf.ByPrimaryKey[token](e, id)
}

// EnsureToken returns the Token row for (networkId, address), creating
// one with the supplied metadata if none exists yet. Used by callers
// that receive a token they don't necessarily already track (e.g.
// wltswap when a swap lands on a token the user has never held before)
// to surface the new asset in the user's token list without requiring
// an explicit `Token:create` round-trip.
//
// Address is normalised the same way `Token:create` normalises it
// (EVM checksum case, Solana base58 round-trip via [token.validate]),
// so callers can pass whatever shape the upstream provider returned.
//
// Empty `symbol` / `name` are accepted; UI fills in a fallback display
// from the address. `tokenType` left empty defaults to the chain's
// canonical type ("erc20" / "spl-token") in validate().
//
// NOTE: there is no `UNIQUE(Network, Address)` constraint on the Token
// table today, so a transient DB error between lookup and insert could
// produce a duplicate row. Acceptable for the swap path — the user can
// dedupe via Token:delete — but worth tightening if EnsureToken grows
// more callers.
func EnsureToken(e wltintf.Env, networkId *xuid.XUID, address, symbol, name string, decimals int, tokenType string) (*token, error) {
	if networkId == nil {
		return nil, errors.New("network is required")
	}
	if address == "" {
		return nil, errors.New("address is required")
	}
	t := &token{
		Network:  networkId,
		Address:  address,
		Symbol:   symbol,
		Name:     name,
		Decimals: decimals,
		Type:     tokenType,
	}
	if err := t.validate(e); err != nil {
		return nil, err
	}

	if existing, err := psql.Get[token](e, map[string]any{
		"Network": networkId,
		"Address": t.Address,
	}); err == nil {
		return existing, nil
	}

	var err error
	t.Id, err = xuid.NewRandom("tok")
	if err != nil {
		return nil, err
	}
	if err := t.save(e); err != nil {
		return nil, err
	}
	return t, nil
}

// Exported accessors for external callers (e.g. wlttx for ERC-20 transfer encoding).

func (t *token) GetAddress() string     { return t.Address }
func (t *token) GetDecimals() int       { return t.Decimals }
func (t *token) GetType() string        { return t.Type }
func (t *token) GetNetwork() *xuid.XUID { return t.Network }
func (t *token) GetName() string        { return t.Name }
func (t *token) GetSymbol() string      { return t.Symbol }

// LookupTokenByMint returns the Token row for (networkId, address), or
// nil if no row exists. Distinguishes "not found" (nil, nil) from
// "lookup failed" (nil, err). Used by callers (e.g. wltbase asset
// enrichment) that want to overlay user-saved metadata on top of a
// chain-fetched balance list without erroring out when the mint isn't
// tracked.
// TokensByNetwork returns every registered Token row for the given network.
// Used by Asset:list to enumerate the user's ERC-20 tokens (the Solana path
// discovers tokens on-chain instead; EVM has no cheap on-chain enumeration,
// so the registry the user builds via Token:create / Token:discoverToken is
// the source of truth).
func TokensByNetwork(e wltintf.Env, networkId *xuid.XUID) ([]*token, error) {
	if networkId == nil {
		return nil, nil
	}
	return psql.Fetch[token](e, map[string]any{"Network": networkId})
}

func LookupTokenByMint(e wltintf.Env, networkId *xuid.XUID, address string) (*token, error) {
	if networkId == nil || address == "" {
		return nil, nil
	}
	t, err := psql.Get[token](e, map[string]any{
		"Network": networkId,
		"Address": address,
	})
	if err != nil {
		return nil, nil
	}
	return t, nil
}

func (t *token) ApiDelete(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	_, err := psql.ForceDelete[token](e, map[string]any{"Id": t.Id})
	return err
}

func (t *token) ApiUpdate(ctx *apirouter.Context) error {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return errors.New("failed to get env")
	}

	updated := false

	if v, ok := apirouter.GetParam[string](ctx, "Name"); ok {
		t.Name = sanitizeTokenText(v, maxTokenNameLen)
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "Symbol"); ok {
		t.Symbol = sanitizeTokenText(v, maxTokenSymbolLen)
		updated = true
	}
	if v, ok := apirouter.GetParam[int](ctx, "Decimals"); ok {
		if v < 0 || v > maxTokenDecimals {
			return fmt.Errorf("Decimals must be between 0 and %d", maxTokenDecimals)
		}
		t.Decimals = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "Logo"); ok {
		t.Logo = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "Memo"); ok {
		t.Memo = v
		updated = true
	}
	if v, ok := apirouter.GetParam[string](ctx, "Type"); ok {
		t.Type = v
		updated = true
	}

	if !updated {
		return nil
	}
	return t.save(e)
}

func apiListToken(ctx *apirouter.Context) (any, error) {
	return wltintf.ListHelper[token](ctx, "Name ASC", "Name", "Symbol", "Address", "Type")
}

func apiFetchToken(ctx *apirouter.Context, in struct{ Id string }) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	id, err := xuid.Parse(in.Id)
	if err != nil {
		return nil, err
	}

	return TokenById(e, id)
}

// resolveNetworkRef accepts a network reference in either form the clients
// use and returns the network's xuid:
//
//   - a network xuid ("net-…"), or
//   - the canonical "<type>.<chainId>" key (e.g. "evm.137", "solana.mainnet")
//     — what Asset.network and the Dart Token API send.
//
// The canonical form is the one that previously blew up as
// "invalid UUID length: 7" (e.g. "evm.137") because Token:create /
// Token:discoverToken parsed Network directly as an xuid. Network existence
// is validated by the caller (NetworkById); this only maps ref → id.
func resolveNetworkRef(ref string) (*xuid.XUID, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("Network is required")
	}
	// A real network xuid has dashes ("net-…"); the canonical key uses dots.
	if id, err := xuid.Parse(ref); err == nil {
		return id, nil
	}
	if i := strings.IndexByte(ref, '.'); i > 0 && i < len(ref)-1 {
		return wltnet.NetworkIdForTypeAndChainId(ref[:i], ref[i+1:]), nil
	}
	return nil, fmt.Errorf("invalid network reference %q (want a net-… id or \"<type>.<chainId>\")", ref)
}

// apiCreateToken takes Network as a string (xuid OR "<type>.<chainId>") rather
// than binding it straight into token.Network (*xuid.XUID), which rejected the
// canonical "evm.137" form with "invalid UUID length: 7".
func apiCreateToken(ctx *apirouter.Context, in struct {
	Name     string
	Symbol   string
	Address  string
	Decimals int
	Type     string
	Network  string
	Logo     string
	Memo     string
}) (any, error) {
	e := wltintf.GetEnv(ctx)
	if e == nil {
		return nil, errors.New("failed to get env")
	}

	netId, err := resolveNetworkRef(in.Network)
	if err != nil {
		return nil, err
	}

	t := &token{
		Name:     in.Name,
		Symbol:   in.Symbol,
		Address:  in.Address,
		Decimals: in.Decimals,
		Type:     in.Type,
		Network:  netId,
		Logo:     in.Logo,
		Memo:     in.Memo,
	}

	if err := t.validate(e); err != nil {
		return nil, err
	}

	t.Id, err = xuid.NewRandom("tok")
	if err != nil {
		return nil, err
	}

	if err := t.save(e); err != nil {
		return nil, err
	}

	return t, nil
}
