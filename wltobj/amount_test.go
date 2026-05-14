package wltobj

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"
)

func TestNewAmount(t *testing.T) {
	a := NewAmount(12345, 2)
	if a.String() != "123.45" {
		t.Errorf("expected 123.45, got %s", a.String())
	}
	if a.Exp() != 2 {
		t.Errorf("expected exp=2, got %d", a.Exp())
	}
	if a.Value().Int64() != 12345 {
		t.Errorf("expected value=12345, got %d", a.Value().Int64())
	}
}

func TestNewAmountZeroExp(t *testing.T) {
	a := NewAmount(42, 0)
	if a.String() != "42" {
		t.Errorf("expected 42, got %s", a.String())
	}
}

func TestAmountString(t *testing.T) {
	tests := []struct {
		value    int64
		decimals int
		expected string
	}{
		{0, 0, "0"},
		{0, 2, "0.00"},
		{1, 2, "0.01"},
		{10, 2, "0.10"},
		{100, 2, "1.00"},
		{12345, 3, "12.345"},
		{5, 5, "0.00005"},
		{-12345, 2, "-123.45"},
		{999, 0, "999"},
	}
	for _, tt := range tests {
		a := NewAmount(tt.value, tt.decimals)
		if s := a.String(); s != tt.expected {
			t.Errorf("NewAmount(%d, %d).String() = %q, want %q", tt.value, tt.decimals, s, tt.expected)
		}
	}
}

func TestAmountFromString(t *testing.T) {
	tests := []struct {
		input    string
		decimals int
		expected string
	}{
		{"123.45", 0, "123.45"},
		{"0.001", 0, "0.001"},
		{"42", 0, "42"},
		{"1e2", 0, "100"},
		{"1.5e3", 0, "1500"},
		{"1e-2", 0, "0.01"},
		{"100", 2, "100.00000"},
	}
	for _, tt := range tests {
		a, err := NewAmountFromString(tt.input, tt.decimals)
		if err != nil {
			t.Errorf("NewAmountFromString(%q, %d) error: %v", tt.input, tt.decimals, err)
			continue
		}
		if s := a.String(); s != tt.expected {
			t.Errorf("NewAmountFromString(%q, %d).String() = %q, want %q", tt.input, tt.decimals, s, tt.expected)
		}
	}
}

func TestAmountFromStringErrors(t *testing.T) {
	_, err := NewAmountFromString("notanumber", 0)
	if err == nil {
		t.Error("expected error for invalid string")
	}

	_, err = NewAmountFromString("12.34.56", 0)
	if err == nil {
		t.Error("expected error for multiple dots")
	}

	_, err = NewAmountFromString("1eXX", 0)
	if err == nil {
		t.Error("expected error for bad exponent")
	}
}

func TestAmountFromFloat64(t *testing.T) {
	a, _ := NewAmountFromFloat64(1.5, 8)
	if s := a.String(); s != "1.50000000" {
		t.Errorf("expected 1.50000000, got %s", s)
	}

	a, _ = NewAmountFromFloat64(0.0, 5)
	if !a.IsZero() {
		t.Error("expected zero")
	}
}

func TestAmountFromFloat(t *testing.T) {
	// Test with decimals <= 0 (auto-detect)
	f := big.NewFloat(3.14159)
	a, _ := NewAmountFromFloat(f, 0)
	if a.Exp() < 5 {
		t.Errorf("expected exp >= 5, got %d", a.Exp())
	}

	// Test with decimals <= 0 and no decimal point
	f = big.NewFloat(42.0)
	a, _ = NewAmountFromFloat(f, -1)
	if a.Exp() < 5 {
		t.Errorf("expected exp >= 5 for auto-detect, got %d", a.Exp())
	}
}

func TestAmountRaw(t *testing.T) {
	v := big.NewInt(999)
	a := NewAmountRaw(v, 3)
	if a.String() != "0.999" {
		t.Errorf("expected 0.999, got %s", a.String())
	}
}

func TestAmountDup(t *testing.T) {
	a := NewAmount(100, 2)
	b := a.Dup()
	b.SetExp(0)
	if a.Exp() != 2 {
		t.Error("Dup should create independent copy")
	}

	var nilAmt *Amount
	if nilAmt.Dup() != nil {
		t.Error("Dup of nil should be nil")
	}
}

func TestAmountAdd(t *testing.T) {
	a := NewAmount(100, 2) // 1.00
	b := NewAmount(250, 2) // 2.50
	c := new(Amount)
	c.value = new(big.Int)
	c.exp = 2
	c.Add(a, b)
	if c.String() != "3.50" {
		t.Errorf("expected 3.50, got %s", c.String())
	}
}

func TestAmountAddDiffExp(t *testing.T) {
	a := NewAmount(1, 0)   // 1
	b := NewAmount(500, 3) // 0.500
	c := NewAmount(0, 3)
	c.Add(a, b)
	if c.String() != "1.500" {
		t.Errorf("expected 1.500, got %s", c.String())
	}
}

func TestAmountSub(t *testing.T) {
	a := NewAmount(500, 2) // 5.00
	b := NewAmount(150, 2) // 1.50
	c := NewAmount(0, 2)
	c.Sub(a, b)
	if c.String() != "3.50" {
		t.Errorf("expected 3.50, got %s", c.String())
	}
}

func TestAmountMul(t *testing.T) {
	a := NewAmount(200, 2) // 2.00
	b := NewAmount(300, 2) // 3.00
	c := NewAmount(0, 2)
	c.Mul(a, b)
	if c.String() != "6.00" {
		t.Errorf("expected 6.00, got %s", c.String())
	}
}

func TestAmountMulNilValue(t *testing.T) {
	a := NewAmount(200, 2)
	b := NewAmount(300, 2)
	c := &Amount{exp: 2}
	c.Mul(a, b)
	if c.String() != "6.00" {
		t.Errorf("expected 6.00, got %s", c.String())
	}
}

func TestAmountDiv(t *testing.T) {
	a := NewAmount(600, 2) // 6.00
	b := NewAmount(200, 2) // 2.00
	c := NewAmount(0, 2)
	c.Div(a, b)
	if c.String() != "3.00" {
		t.Errorf("expected 3.00, got %s", c.String())
	}
}

func TestAmountSetExp(t *testing.T) {
	a := NewAmount(12345, 2) // 123.45
	a.SetExp(4)
	if a.String() != "123.4500" {
		t.Errorf("expected 123.4500, got %s", a.String())
	}

	// Reduce exp (rounds)
	b := NewAmount(12345, 4) // 1.2345
	b.SetExp(2)
	if b.String() != "1.23" {
		t.Errorf("expected 1.23, got %s", b.String())
	}

	// Same exp (no-op)
	c := NewAmount(100, 2)
	c.SetExp(2)
	if c.String() != "1.00" {
		t.Errorf("expected 1.00, got %s", c.String())
	}
}

func TestAmountSetExpNegative(t *testing.T) {
	// Rounding negative values
	a := NewAmount(-12345, 4) // -1.2345
	a.SetExp(2)
	if a.String() != "-1.23" {
		t.Errorf("expected -1.23, got %s", a.String())
	}
}

func TestAmountIsZero(t *testing.T) {
	a := NewAmount(0, 2)
	if !a.IsZero() {
		t.Error("expected IsZero true")
	}
	b := NewAmount(1, 2)
	if b.IsZero() {
		t.Error("expected IsZero false")
	}
}

func TestAmountSign(t *testing.T) {
	if NewAmount(5, 0).Sign() != 1 {
		t.Error("expected positive sign")
	}
	if NewAmount(-5, 0).Sign() != -1 {
		t.Error("expected negative sign")
	}
	if NewAmount(0, 0).Sign() != 0 {
		t.Error("expected zero sign")
	}

	// nil value
	a := &Amount{}
	if a.Sign() != 0 {
		t.Error("expected zero sign for nil value")
	}
}

func TestAmountCmp(t *testing.T) {
	a := NewAmount(100, 2)
	b := NewAmount(200, 2)
	if a.Cmp(b) != -1 {
		t.Error("expected -1")
	}
	if b.Cmp(a) != 1 {
		t.Error("expected 1")
	}
	if a.Cmp(a) != 0 {
		t.Error("expected 0")
	}
}

func TestAmountCmpPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for different exponents")
		}
	}()
	a := NewAmount(100, 2)
	b := NewAmount(100, 3)
	a.Cmp(b)
}

func TestAmountFloat(t *testing.T) {
	a := NewAmount(12345, 2)
	f := a.Float()
	v, _ := f.Float64()
	if v != 123.45 {
		t.Errorf("expected 123.45, got %f", v)
	}

	// Zero amount
	z := NewAmount(0, 2)
	fz := z.Float()
	vz, _ := fz.Float64()
	if vz != 0 {
		t.Errorf("expected 0, got %f", vz)
	}
}

func TestAmountNeg(t *testing.T) {
	a := NewAmount(100, 2) // 1.00
	b := a.Neg()
	if b.String() != "-1.00" {
		t.Errorf("expected -1.00, got %s", b.String())
	}
	// Original unchanged
	if a.String() != "1.00" {
		t.Error("Neg should not modify original")
	}
}

func TestAmountReciprocal(t *testing.T) {
	a := NewAmount(2000000, 6) // 2.000000
	r, _ := a.Reciprocal()
	if s := r.String(); s != "0.500000" {
		t.Errorf("expected 0.500000, got %s", s)
	}
}

func TestAmountJSON(t *testing.T) {
	a := NewAmount(12345, 2)
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	b := &Amount{}
	err = json.Unmarshal(data, b)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if b.String() != "123.45" {
		t.Errorf("expected 123.45, got %s", b.String())
	}
}

func TestAmountJSONNilValue(t *testing.T) {
	a := &Amount{exp: 2}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	// Should marshal with "0"
	var raw map[string]any
	json.Unmarshal(data, &raw)
	if raw["v"] != "0" {
		t.Errorf("expected v=0, got %v", raw["v"])
	}
}

func TestAmountUnmarshalJSONString(t *testing.T) {
	a := &Amount{}
	err := json.Unmarshal([]byte(`"42.5"`), a)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if a.String() != "42.5" {
		t.Errorf("expected 42.5, got %s", a.String())
	}
}

func TestAmountUnmarshalJSONNumber(t *testing.T) {
	a := &Amount{}
	err := json.Unmarshal([]byte(`123.45`), a)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if a.String() != "123.45" {
		t.Errorf("expected 123.45, got %s", a.String())
	}
}

func TestAmountUnmarshalJSONObject(t *testing.T) {
	a := &Amount{}
	err := json.Unmarshal([]byte(`{"v":"12345","e":2}`), a)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if a.String() != "123.45" {
		t.Errorf("expected 123.45, got %s", a.String())
	}
}

func TestAmountUnmarshalJSONObjectWithFloat(t *testing.T) {
	a := &Amount{}
	err := json.Unmarshal([]byte(`{"f":"42.5"}`), a)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if a.String() != "42.5" {
		t.Errorf("expected 42.5 got %s", a.String())
	}
}

func TestAmountUnmarshalJSONObjectErrors(t *testing.T) {
	// Bad v field
	a := &Amount{}
	err := json.Unmarshal([]byte(`{"v":"notanumber","e":2}`), a)
	if err == nil {
		t.Error("expected error for bad v")
	}

	// Object with no useful fields
	a = &Amount{}
	err = json.Unmarshal([]byte(`{"x":1}`), a)
	if err == nil {
		t.Error("expected error for object without v or f")
	}

	// Unsupported type
	a = &Amount{}
	err = json.Unmarshal([]byte(`true`), a)
	if err == nil {
		t.Error("expected error for bool")
	}
}

func TestAmountBinary(t *testing.T) {
	a := NewAmount(12345, 2)
	data, err := a.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal binary error: %v", err)
	}

	b := &Amount{}
	err = b.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("unmarshal binary error: %v", err)
	}
	if b.String() != "123.45" {
		t.Errorf("expected 123.45, got %s", b.String())
	}
}

func TestAmountUnmarshalBinaryErrors(t *testing.T) {
	a := &Amount{}
	if err := a.UnmarshalBinary([]byte{0}); err == nil {
		t.Error("expected error for too short data")
	}

	if err := a.UnmarshalBinary([]byte{1, 0}); err == nil {
		t.Error("expected error for invalid version")
	}
}

func TestAmountBytes(t *testing.T) {
	a := NewAmount(100, 2)
	b := a.Bytes()
	if len(b) == 0 {
		t.Error("expected non-empty bytes")
	}
	if b[0] != 0 {
		t.Error("expected version byte 0")
	}
}

func TestAmountUnmarshalBinaryBadVarint(t *testing.T) {
	// Version 0 but invalid varint (0x80 needs continuation bytes)
	a := &Amount{}
	err := a.UnmarshalBinary([]byte{0, 0x80})
	if err == nil {
		t.Error("expected error for invalid varint encoding")
	}
}

func TestAmountSubDiffExp(t *testing.T) {
	a := NewAmount(5000, 3) // 5.000
	b := NewAmount(150, 2)  // 1.50
	c := NewAmount(0, 3)
	c.Sub(a, b)
	if c.String() != "3.500" {
		t.Errorf("expected 3.500, got %s", c.String())
	}
}

func TestAmountFromStringIntegerWithExponent(t *testing.T) {
	// Test integer with no decimal point but negative exponent
	a, err := NewAmountFromString("5e-3", 0)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if a.String() != "0.005" {
		t.Errorf("expected 0.005, got %s", a.String())
	}

	// Integer with positive exponent
	a, err = NewAmountFromString("5e2", 0)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if a.String() != "500" {
		t.Errorf("expected 500, got %s", a.String())
	}
}

func TestAmountFromStringBadInteger(t *testing.T) {
	_, err := NewAmountFromString("abc", 0)
	if err == nil {
		t.Error("expected error for bad integer string")
	}
}

func TestAmountUnmarshalJSONBadJSON(t *testing.T) {
	a := &Amount{}
	err := a.UnmarshalJSON([]byte("not json at all {{{"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestAmountScanBadEField(t *testing.T) {
	a := &Amount{}
	err := a.Scan(map[string]any{"v": "100", "e": "notanumber"})
	if err == nil {
		t.Error("expected error for bad e field")
	}
}

func TestAmountScanFloatField(t *testing.T) {
	a := &Amount{}
	// Map with f but bad value
	err := a.Scan(map[string]any{"f": 42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJSONStringSliceValueMarshalError(t *testing.T) {
	// Normal case - just verify round-trip
	s := JSONStringSlice{"hello", "world"}
	v, err := s.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}
	s2 := &JSONStringSlice{}
	err = s2.Scan(v)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(*s2) != 2 || (*s2)[0] != "hello" || (*s2)[1] != "world" {
		t.Errorf("round-trip failed: %v", *s2)
	}
}

func TestJSONBigIntUnmarshalJSONBadJSON(t *testing.T) {
	j := &JSONBigInt{}
	err := j.UnmarshalJSON([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestNewAmountMax(t *testing.T) {
	a := NewAmountMax(18)
	if !a.IsMax() {
		t.Error("expected IsMax true")
	}
	if a.Sign() != 0 {
		t.Errorf("Sign() = %d, want 0 for MAX (no concrete value yet)", a.Sign())
	}
	if a.Value() != nil {
		t.Errorf("Value() = %v, want nil for MAX", a.Value())
	}
	if a.Exp() != 18 {
		t.Errorf("Exp() = %d, want 18 (preserved decimals)", a.Exp())
	}

	regular := NewAmountRaw(big.NewInt(123), 6)
	if regular.IsMax() {
		t.Error("regular Amount should not be MAX")
	}
}

func TestAmountMaxJSONRoundTrip(t *testing.T) {
	orig := NewAmountMax(18)
	raw, err := orig.MarshalJSON()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Should encode as the MAX sentinel string with the decimals preserved.
	if !bytes.Contains(raw, []byte(`"v":"MAX"`)) {
		t.Errorf("expected MAX sentinel in JSON, got %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"e":18`)) {
		t.Errorf("expected exponent in JSON, got %s", raw)
	}

	got := &Amount{}
	if err := got.UnmarshalJSON(raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !got.IsMax() {
		t.Error("round-tripped value lost IsMax")
	}
	if got.Exp() != 18 {
		t.Errorf("round-tripped exp = %d, want 18", got.Exp())
	}

	// Bare string form too — apps that hand-craft a JSON body with
	// just "MAX" should also resolve.
	bare := &Amount{}
	if err := bare.UnmarshalJSON([]byte(`"MAX"`)); err != nil {
		t.Fatalf("bare string Unmarshal: %v", err)
	}
	if !bare.IsMax() {
		t.Error("bare string \"MAX\" did not produce IsMax")
	}
}

func TestAmountMaxSetMaxResolved(t *testing.T) {
	a := NewAmountMax(18)
	if err := a.SetMaxResolved(big.NewInt(1_000_000_000)); err != nil {
		t.Fatalf("SetMaxResolved: %v", err)
	}
	if a.IsMax() {
		t.Error("after SetMaxResolved, IsMax should be false")
	}
	if a.Value().Cmp(big.NewInt(1_000_000_000)) != 0 {
		t.Errorf("Value() = %v, want 1_000_000_000", a.Value())
	}

	// SetMaxResolved on a non-MAX Amount is an error — guards against
	// accidental mutation of a regular Amount via the wrong API.
	plain := NewAmountRaw(big.NewInt(7), 0)
	if err := plain.SetMaxResolved(big.NewInt(99)); err == nil {
		t.Error("expected error setting MaxResolved on non-MAX Amount")
	}

	// Nil value rejected — defensive against callers that forget to
	// initialise a *big.Int before passing it in.
	max := NewAmountMax(0)
	if err := max.SetMaxResolved(nil); err == nil {
		t.Error("expected error for nil value")
	}
}
