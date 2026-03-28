package wltobj

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"math/big"
)

// JSONBigInt wraps *big.Int for SQL JSON serialization
type JSONBigInt struct {
	*big.Int
}

func (j JSONBigInt) Value() (driver.Value, error) {
	if j.Int == nil {
		return nil, nil
	}
	return j.Int.String(), nil
}

func (j *JSONBigInt) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		j.Int = nil
		return nil
	case string:
		j.Int = new(big.Int)
		if _, ok := j.Int.SetString(v, 10); !ok {
			return fmt.Errorf("failed to parse big.Int from %q", v)
		}
		return nil
	case []byte:
		j.Int = new(big.Int)
		if _, ok := j.Int.SetString(string(v), 10); !ok {
			return fmt.Errorf("failed to parse big.Int from bytes")
		}
		return nil
	default:
		return fmt.Errorf("unsupported type %T for JSONBigInt", src)
	}
}

func (j JSONBigInt) MarshalJSON() ([]byte, error) {
	if j.Int == nil {
		return []byte("null"), nil
	}
	return json.Marshal(j.Int.String())
}

func (j *JSONBigInt) UnmarshalJSON(b []byte) error {
	var s *string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == nil {
		j.Int = nil
		return nil
	}
	j.Int = new(big.Int)
	if _, ok := j.Int.SetString(*s, 10); !ok {
		return fmt.Errorf("failed to parse big.Int from JSON")
	}
	return nil
}

// JSONStringSlice wraps []string for SQL JSON serialization
type JSONStringSlice []string

func (s JSONStringSlice) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	b, err := json.Marshal([]string(s))
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (s *JSONStringSlice) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*s = nil
		return nil
	case string:
		return json.Unmarshal([]byte(v), (*[]string)(s))
	case []byte:
		return json.Unmarshal(v, (*[]string)(s))
	default:
		return fmt.Errorf("unsupported type %T for JSONStringSlice", src)
	}
}
