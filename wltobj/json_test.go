package wltobj

import (
	"database/sql/driver"
	"encoding/json"
	"math/big"
	"testing"
)

func TestJSONBigIntValue(t *testing.T) {
	j := JSONBigInt{Int: big.NewInt(12345)}
	v, err := j.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}
	if v != "12345" {
		t.Errorf("expected 12345, got %v", v)
	}

	// Nil Int
	j2 := JSONBigInt{}
	v2, err := j2.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}
	if v2 != nil {
		t.Errorf("expected nil, got %v", v2)
	}
}

func TestJSONBigIntScan(t *testing.T) {
	tests := []struct {
		name     string
		input    driver.Value
		expected string
		isNil    bool
	}{
		{"nil", nil, "", true},
		{"string", "12345", "12345", false},
		{"bytes", []byte("67890"), "67890", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &JSONBigInt{}
			err := j.Scan(tt.input)
			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}
			if tt.isNil {
				if j.Int != nil {
					t.Error("expected nil Int")
				}
			} else {
				if j.Int.String() != tt.expected {
					t.Errorf("expected %s, got %s", tt.expected, j.Int.String())
				}
			}
		})
	}
}

func TestJSONBigIntScanErrors(t *testing.T) {
	j := &JSONBigInt{}
	if err := j.Scan("notanumber"); err == nil {
		t.Error("expected error for invalid string")
	}

	if err := j.Scan([]byte("notanumber")); err == nil {
		t.Error("expected error for invalid bytes")
	}

	if err := j.Scan(12345); err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestJSONBigIntMarshalJSON(t *testing.T) {
	j := JSONBigInt{Int: big.NewInt(42)}
	data, err := json.Marshal(j)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if string(data) != `"42"` {
		t.Errorf("expected \"42\", got %s", string(data))
	}

	// Nil
	j2 := JSONBigInt{}
	data2, err := json.Marshal(j2)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if string(data2) != "null" {
		t.Errorf("expected null, got %s", string(data2))
	}
}

func TestJSONBigIntUnmarshalJSON(t *testing.T) {
	j := &JSONBigInt{}
	err := json.Unmarshal([]byte(`"12345"`), j)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if j.Int.String() != "12345" {
		t.Errorf("expected 12345, got %s", j.Int.String())
	}

	// Null
	j2 := &JSONBigInt{Int: big.NewInt(1)}
	err = json.Unmarshal([]byte(`null`), j2)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if j2.Int != nil {
		t.Error("expected nil after unmarshaling null")
	}

	// Invalid
	j3 := &JSONBigInt{}
	err = json.Unmarshal([]byte(`"notanumber"`), j3)
	if err == nil {
		t.Error("expected error for invalid number string")
	}
}

func TestJSONStringSliceValue(t *testing.T) {
	s := JSONStringSlice{"a", "b", "c"}
	v, err := s.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}
	if v != `["a","b","c"]` {
		t.Errorf("expected [\"a\",\"b\",\"c\"], got %v", v)
	}

	// Nil
	var s2 JSONStringSlice
	v2, err := s2.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}
	if v2 != nil {
		t.Errorf("expected nil, got %v", v2)
	}
}

func TestJSONStringSliceScan(t *testing.T) {
	s := &JSONStringSlice{}
	err := s.Scan(`["x","y"]`)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(*s) != 2 || (*s)[0] != "x" || (*s)[1] != "y" {
		t.Errorf("unexpected result: %v", *s)
	}

	// From bytes
	s2 := &JSONStringSlice{}
	err = s2.Scan([]byte(`["a"]`))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(*s2) != 1 || (*s2)[0] != "a" {
		t.Errorf("unexpected result: %v", *s2)
	}

	// Nil
	s3 := &JSONStringSlice{}
	err = s3.Scan(nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if *s3 != nil {
		t.Error("expected nil after scanning nil")
	}

	// Unsupported type
	s4 := &JSONStringSlice{}
	err = s4.Scan(12345)
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}
