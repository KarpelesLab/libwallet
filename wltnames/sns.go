package wltnames

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/base58"
	"github.com/KarpelesLab/ethrpc"
	"github.com/KarpelesLab/libwallet/wltintf"
	"github.com/KarpelesLab/libwallet/wltnet"
)

// SNS Program ID (Bonfida Solana Name Service).
const snsProgramID = "namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX"

// The ".sol" TLD parent is a hashed constant: hashv(hashPrefix + ".sol")
// where hashPrefix is SPL_NAME_SERVICE_HASH_PREFIX.
const snsHashPrefix = "SPL Name Service"

// solDomainParent is the account key for the ".sol" root domain.
// This is a well-known constant.
const solDomainParent = "58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx"

// ResolveSNS resolves a Solana name (e.g. "foo.sol") to a Solana address.
// Returns a base58-encoded 32-byte public key.
func ResolveSNS(e wltintf.Env, name string) (string, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return "", errors.New("empty name")
	}
	// Reject confusable / mixed-script / non-ASCII labels before
	// resolving so a homograph name cannot silently resolve to an
	// attacker's address in a payment flow.
	if err := validateResolvableName(name); err != nil {
		return "", err
	}
	if !strings.HasSuffix(name, ".sol") {
		return "", errors.New("SNS names must end with .sol")
	}
	label := strings.TrimSuffix(name, ".sol")
	if label == "" || strings.Contains(label, ".") {
		return "", errors.New("SNS supports single-label .sol names only")
	}

	// Find the Solana mainnet network
	netID := wltnet.NetworkIdForTypeAndChainId("solana", "mainnet")
	net, err := wltnet.NetworkById(e, netID)
	if err != nil {
		return "", fmt.Errorf("SNS requires Solana mainnet network: %w", err)
	}

	// Compute the domain account key: derived from hashed name + SNS program
	parentBytes, err := base58.Bitcoin.Decode(solDomainParent)
	if err != nil {
		return "", fmt.Errorf("SNS parent decode: %w", err)
	}
	nameHash := sha256Sum([]byte(snsHashPrefix + label))

	domainKey, err := createProgramAddress(nameHash, nil, parentBytes, snsProgramID)
	if err != nil {
		return "", fmt.Errorf("SNS domain key: %w", err)
	}

	// Fetch the domain account
	acctInfo, err := rpcGetAccountInfo(net, domainKey)
	if err != nil {
		return "", fmt.Errorf("SNS getAccountInfo: %w", err)
	}
	if len(acctInfo) < 96 {
		return "", fmt.Errorf("SNS domain data too short (%d bytes)", len(acctInfo))
	}

	// NameRecordHeader layout: parent(32) + owner(32) + class(32) + data
	// The owner at offset 32..64 is the resolved address.
	parent := acctInfo[0:32]
	owner := acctInfo[32:64]
	// Verify the record's parent equals the ".sol" root domain. Without
	// this an account whose data merely happens to be >=96 bytes (or a
	// record under a different parent) could be accepted as a .sol
	// resolution and pay out to an unrelated owner.
	if !bytes.Equal(parent, parentBytes) {
		return "", errors.New("SNS record parent mismatch")
	}
	// Reject a zeroed owner (uninitialized / cleared record) rather than
	// returning the all-zeros address as a payment target.
	if isZeroBytes(owner) {
		return "", errors.New("SNS name resolves to zero owner")
	}
	return base58.Bitcoin.Encode(owner), nil
}

// isZeroBytes reports whether b is all zero bytes (mirrors ENS
// isZeroAddress for the raw 32-byte Solana key form).
func isZeroBytes(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// createProgramAddress mimics Solana's create_program_address for SNS.
// It takes name hash, optional class, parent (as bytes), and the program ID (base58).
// Returns the derived account address as base58.
func createProgramAddress(nameHash, class, parent []byte, programIDBase58 string) (string, error) {
	programID, err := base58.Bitcoin.Decode(programIDBase58)
	if err != nil {
		return "", err
	}
	if class == nil {
		class = make([]byte, 32)
	}
	if len(parent) != 32 {
		parent = make([]byte, 32)
	}
	// SNS uses getHashedName(name) || class || parent
	seed := append(nameHash, class...)
	seed = append(seed, parent...)

	// findProgramAddress: try bumps 255..0 and return the first candidate
	// that is NOT a valid ed25519 point (off-curve), exactly as Solana's
	// PublicKey.findProgramAddress does. The previous loop always returned
	// the bump-255 hash without the off-curve check, so for any domain
	// whose canonical bump is < 255 (the common case) it derived the wrong
	// account key.
	for bump := 255; bump >= 0; bump-- {
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte{byte(bump)})
		h.Write(programID)
		h.Write([]byte("ProgramDerivedAddress"))
		pda := h.Sum(nil)

		if isOnCurveEd25519(pda) {
			// On-curve points are not valid PDAs; keep decrementing.
			continue
		}
		return base58.Bitcoin.Encode(pda), nil
	}
	return "", errors.New("unable to derive PDA")
}

// isOnCurveEd25519 reports whether the 32-byte value is a valid (canonical)
// ed25519 curve point encoding. A valid PDA must be OFF the curve, so
// createProgramAddress skips any bump whose hash lands on the curve.
func isOnCurveEd25519(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	_, err := new(edwards25519.Point).SetBytes(b)
	return err == nil
}

// rpcGetAccountInfo fetches a Solana account's data (base64-decoded).
func rpcGetAccountInfo(net *wltnet.Network, address string) ([]byte, error) {
	type respValue struct {
		Value struct {
			Data []string `json:"data"`
		} `json:"value"`
	}
	r, err := ethrpc.ReadAs[respValue](net.DoRPC("getAccountInfo", address, map[string]string{"encoding": "base64"}))
	if err != nil {
		return nil, err
	}
	if len(r.Value.Data) == 0 {
		return nil, errors.New("SNS account not found or empty")
	}
	return base64.StdEncoding.DecodeString(r.Value.Data[0])
}
