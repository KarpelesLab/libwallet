package wltobj

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/KarpelesLab/typutil"
)

var ErrAmountParseFailed = errors.New("failed to parse provided amount")

// Amount represents a fixed-point decimal value with arbitrary precision.
// It uses a big.Int for the value and an exponent to represent the decimal position.
// For example, 123.456 would be stored as value=123456 and exp=3.
// This allows for precise decimal arithmetic without floating-point errors.
//
// Special MAX sentinel — see [NewAmountMax] / [Amount.IsMax]: a deferred
// "use the maximum sendable" marker that the build path resolves at the
// last possible moment with the actual tx data. Lets the host pass MAX
// as a tx Amount and trust libwallet to compute balance - actual-fee at
// build/sign time, eliminating the maxSendable→signAndSend race where
// gas price or balance can drift between the two calls.
//
// MAX amounts must be resolved (via [Amount.SetMaxResolved]) before any
// arithmetic — Value() returns nil and Sign() returns 0, but most other
// operations panic to fail loudly if a MAX leaks past the build path.
type Amount struct {
	value *big.Int // The integer value (significand). nil when isMax.
	exp   int      // The exponent (number of decimal places).
	isMax bool     // True for the MAX sentinel; resolved at build time.
}

// NewAmount returns a new Amount object set to the specific value and decimals.
// For example, NewAmount(12345, 2) creates the value 123.45
func NewAmount(value int64, decimals int) *Amount {
	a := &Amount{
		value: big.NewInt(value),
		exp:   decimals,
	}
	return a
}

// Float converts the Amount to a big.Float representation.
func (a Amount) Float() *big.Float {
	if a.Sign() == 0 {
		return new(big.Float)
	}
	res := new(big.Float).SetInt(a.value)

	// divide by 10**exp
	return res.Quo(res, exp10f(a.exp))
}

// NewAmountFromFloat64 returns a new Amount initialized with the value f
// stored with the specified number of decimal places.
func NewAmountFromFloat64(f float64, exp int) (*Amount, big.Accuracy) {
	return NewAmountFromFloat(big.NewFloat(f), exp)
}

// NewAmountFromFloat returns a new Amount initialized with the big.Float value
// stored with the specified number of decimal places.
func NewAmountFromFloat(f *big.Float, decimals int) (*Amount, big.Accuracy) {
	if decimals <= 0 {
		s := f.Text('f', -1)
		pos := strings.IndexByte(s, '.')
		if pos == -1 {
			decimals = 5
		} else {
			decimals = len(s) - pos - 1
		}
	}
	if decimals < 5 {
		decimals = 5
	}

	f = new(big.Float).Mul(f, exp10f(decimals))
	f = f.Add(f, big.NewFloat(0.5*float64(f.Sign())))
	val, acc := f.Int(nil)

	a := &Amount{
		value: val,
		exp:   decimals,
	}

	return a, acc
}

// Dup returns a copy of the Amount object so that modifying one won't affect the other
func (a *Amount) Dup() *Amount {
	if a == nil {
		return nil
	}
	res := &Amount{
		value: new(big.Int).Set(a.value),
		exp:   a.exp,
	}
	return res
}

// NewAmountFromString returns a new Amount initialized with the passed string value
func NewAmountFromString(s string, decimals int) (*Amount, error) {
	if decimals == 0 {
		pos := strings.IndexAny(s, "eE")
		extraE := 0
		if pos != -1 {
			v, err := strconv.ParseInt(s[pos+1:], 0, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrAmountParseFailed, err)
			}
			extraE = 0 - int(v)
			s = s[:pos]
		}
		pos = strings.IndexByte(s, '.')
		if pos == -1 {
			v, ok := new(big.Int).SetString(s, 0)
			if !ok {
				return nil, ErrAmountParseFailed
			}
			if extraE < 0 {
				v = v.Mul(v, exp10(0-extraE))
				extraE = 0
			}
			return &Amount{value: v, exp: extraE}, nil
		}
		e := len(s) - pos - 1
		v, ok := new(big.Int).SetString(s[:pos]+s[pos+1:], 10)
		if !ok {
			return nil, ErrAmountParseFailed
		}
		e += extraE
		if e < 0 {
			v = v.Mul(v, exp10(0-e))
			e = 0
		}
		return &Amount{value: v, exp: e}, nil
	}
	f, _, err := big.ParseFloat(s, 0, 1024, big.ToNearestEven)
	if err != nil {
		return nil, err
	}

	a, _ := NewAmountFromFloat(f, decimals)
	return a, nil
}

// NewAmountRaw returns a new Amount initialized with the passed values as is
func NewAmountRaw(v *big.Int, decimals int) *Amount {
	return &Amount{value: v, exp: decimals}
}

// NewAmountMax returns the MAX sentinel — a deferred "use the maximum
// sendable amount" marker. The build path (wlttx Transaction.Validate)
// detects MAX and replaces it with balance - actual-fee, computed
// against the actual tx contents (recipient, calldata) so e.g. native
// EVM swaps reserve the swap's real gas cost rather than the 21000-gas
// EOA-transfer default.
//
// Decimals must match the asset the MAX is being sent in (so the
// resolved amount inherits the right exponent). Pass the same decimals
// you would for [NewAmountRaw].
func NewAmountMax(decimals int) *Amount {
	return &Amount{exp: decimals, isMax: true}
}

// IsMax reports whether this Amount is the MAX sentinel — a deferred
// "use the maximum sendable amount" value the build path will resolve.
// Returns false for the zero Amount and for any Amount with a value
// already set.
func (a Amount) IsMax() bool {
	return a.isMax
}

// SetMaxResolved replaces a MAX sentinel with a concrete value, in
// place. Used by the build path after gas / fee math is known. No-op
// (and returns an error) when called on a non-MAX Amount — the caller
// is presumably mishandling the resolution flow and should be told.
func (a *Amount) SetMaxResolved(v *big.Int) error {
	if !a.isMax {
		return errors.New("SetMaxResolved called on a non-MAX Amount")
	}
	if v == nil {
		return errors.New("SetMaxResolved value cannot be nil")
	}
	a.value = v
	a.isMax = false
	return nil
}

// Mul sets a=x*y and returns a.
func (a *Amount) Mul(x, y *Amount) *Amount {
	if a.value == nil {
		a.value = new(big.Int)
	}
	a.value.Mul(x.value, y.value)
	exp := a.exp
	a.exp = x.exp + y.exp
	return a.SetExp(exp)
}

// Reciprocal returns 1/a in a newly allocated Amount.
func (a Amount) Reciprocal() (*Amount, big.Accuracy) {
	v := new(big.Float).Quo(new(big.Float).SetInt64(1), a.Float())
	return NewAmountFromFloat(v, a.exp)
}

// Neg returns -a (the negation) in a newly allocated Amount.
func (a Amount) Neg() *Amount {
	v := new(big.Int).Neg(a.value)
	return NewAmountRaw(v, a.exp)
}

// Value returns the amount's value *big.Int
func (a Amount) Value() *big.Int {
	return a.value
}

// Exp returns the amount's exp value
func (a Amount) Exp() int {
	return a.exp
}

// SetExp sets the number of decimals (exponent) of the amount.
func (a *Amount) SetExp(e int) *Amount {
	if a.exp == e {
		return a
	}

	if e > a.exp {
		add := e - a.exp
		a.exp = e
		a.value = a.value.Mul(a.value, exp10(add))
		return a
	}

	sub := a.exp - e
	e10 := exp10(sub)
	e10half := new(big.Int).Quo(e10, big.NewInt(2))
	if a.value.Sign() < 0 {
		e10half = e10half.Mul(e10half, big.NewInt(-1))
	}
	a.exp = e
	a.value = a.value.Add(a.value, e10half)
	a.value = a.value.Quo(a.value, exp10(sub))
	return a
}

func (a Amount) String() string {
	s := a.value.Text(10)

	if a.exp == 0 {
		return s
	}

	if len(s) > a.exp {
		p := len(s) - a.exp
		return s[:p] + "." + s[p:]
	}
	if len(s) < a.exp {
		p := a.exp - len(s)
		return "0." + strings.Repeat("0", p) + s
	}

	return "0." + s
}

func (a Amount) IsZero() bool {
	return a.value.BitLen() == 0
}

func (a Amount) Sign() int {
	if a.value == nil {
		return 0
	}
	return a.value.Sign()
}

// Cmp compares two amounts, assuming both have the same exponent
func (a Amount) Cmp(b *Amount) int {
	if a.exp != b.exp {
		panic("only amounts with same exponent can be compared")
	}
	return a.value.Cmp(b.value)
}

// Div sets a=x/y and returns a.
func (a *Amount) Div(x, y *Amount) *Amount {
	x = x.Dup().SetExp(y.exp + a.exp)
	a.value = a.value.Quo(x.value, y.value)
	return a
}

// Add sets a=x+y and returns a.
func (a *Amount) Add(x, y *Amount) *Amount {
	if x.exp != a.exp {
		x = x.Dup().SetExp(a.exp)
	}
	if y.exp != a.exp {
		y = y.Dup().SetExp(a.exp)
	}
	a.value = a.value.Add(x.value, y.value)
	return a
}

// Sub sets a=x-y and returns a.
func (a *Amount) Sub(x, y *Amount) *Amount {
	if x.exp != a.exp {
		x = x.Dup().SetExp(a.exp)
	}
	if y.exp != a.exp {
		y = y.Dup().SetExp(a.exp)
	}
	a.value = a.value.Sub(x.value, y.value)
	return a
}

type amountJson struct {
	Value string  `json:"v"`
	Exp   int     `json:"e"`
	Float float64 `json:"f"`
}

// maxAmountSentinelString is the wire form of the MAX sentinel — a
// distinct value so the existing string-decoding path in Scan picks it
// up automatically without needing a new top-level field.
const maxAmountSentinelString = "MAX"

func (a Amount) MarshalJSON() ([]byte, error) {
	if a.isMax {
		// Round-trip-safe: Scan's string branch picks up "MAX" and
		// rebuilds the sentinel. Decimals are preserved so the resolved
		// amount inherits the right exponent.
		v := &amountJson{Value: maxAmountSentinelString, Exp: a.exp}
		return json.Marshal(v)
	}
	if a.value == nil {
		v := &amountJson{Value: "0", Exp: a.exp}
		return json.Marshal(v)
	}
	f, _ := a.Float().Float64()
	v := &amountJson{Value: a.value.Text(10), Exp: a.exp, Float: f}
	return json.Marshal(v)
}

func (a *Amount) UnmarshalJSON(b []byte) error {
	var v any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	err := dec.Decode(&v)
	if err != nil {
		return err
	}

	return a.Scan(v)
}

func (a *Amount) Scan(v any) error {
	switch in := v.(type) {
	case string:
		if in == maxAmountSentinelString {
			a.value = nil
			a.exp = 0
			a.isMax = true
			return nil
		}
		na, err := NewAmountFromString(in, 0)
		if err != nil {
			return err
		}
		*a = *na
		return nil
	case json.Number:
		na, err := NewAmountFromString(string(in), 0)
		if err != nil {
			return err
		}
		*a = *na
		return nil
	case map[string]any:
		v, vok := in["v"].(string)
		e, eok := in["e"]
		if vok && eok {
			realE, err := typutil.As[int](e)
			if err != nil {
				return err
			}
			if v == maxAmountSentinelString {
				a.value = nil
				a.exp = realE
				a.isMax = true
				return nil
			}
			realV, vok := new(big.Int).SetString(v, 0)
			if !vok {
				return errors.New("failed to parse v")
			}
			a.value = realV
			a.exp = realE
			return nil
		}
		f, fok := in["f"]
		if fok {
			sf, err := typutil.As[string](f)
			if err != nil {
				return err
			}
			na, err := NewAmountFromString(sf, 0)
			if err != nil {
				return err
			}
			*a = *na
			return nil
		}
		return fmt.Errorf("failed to parse object as Amount")
	default:
		return fmt.Errorf("unsupported amount type %T", v)
	}
}

func (a Amount) Bytes() []byte {
	buf := binary.AppendVarint([]byte{0x00}, int64(a.exp))
	return append(buf, a.value.Bytes()...)
}

func (a Amount) MarshalBinary() ([]byte, error) {
	return a.Bytes(), nil
}

func (a *Amount) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return errors.New("data too short")
	}
	if data[0] != 0 {
		return errors.New("invalid version")
	}
	exp, n := binary.Varint(data[1:])
	if n <= 0 {
		return errors.New("invalid amount encoding")
	}

	a.exp = int(exp)
	a.value = new(big.Int).SetBytes(data[n+1:])
	return nil
}

var (
	exp10cache  = make(map[int]*big.Int)
	exp10fcache = make(map[int]*big.Float)
	exp10lock   sync.RWMutex
)

func exp10(v int) *big.Int {
	exp10lock.RLock()
	res, ok := exp10cache[v]
	exp10lock.RUnlock()

	if ok {
		return res
	}

	res = new(big.Int).Exp(new(big.Int).SetInt64(10), new(big.Int).SetInt64(int64(v)), nil)

	exp10lock.Lock()
	defer exp10lock.Unlock()

	exp10cache[v] = res
	return res
}

func exp10f(v int) *big.Float {
	exp10lock.RLock()
	res, ok := exp10fcache[v]
	exp10lock.RUnlock()

	if ok {
		return res
	}

	res = new(big.Float).SetInt(exp10(v))

	exp10lock.Lock()
	defer exp10lock.Unlock()

	exp10fcache[v] = res
	return res
}
