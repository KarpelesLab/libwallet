package wltobj

import (
	"encoding/json"
	"testing"
)

func TestNewTimeId(t *testing.T) {
	tid := NewTimeId()
	if tid.Unix == 0 {
		t.Error("expected non-zero unix timestamp")
	}
}

func TestNewUniqueTimeId(t *testing.T) {
	t1 := NewUniqueTimeId()
	t2 := NewUniqueTimeId()
	if t1.Cmp(*t2) >= 0 {
		t.Error("second unique TimeId should be greater than first")
	}
}

func TestParseTimeId(t *testing.T) {
	tests := []struct {
		input string
		typ   string
		unix  uint64
		nano  uint32
		index uint32
	}{
		{"tx:1000:500:1", "tx", 1000, 500, 1},
		{"1000:500:1", "", 1000, 500, 1},
		{"nil:0:0:0", "nil", 0, 0, 0},
	}
	for _, tt := range tests {
		tid, err := ParseTimeId(tt.input)
		if err != nil {
			t.Errorf("ParseTimeId(%q) error: %v", tt.input, err)
			continue
		}
		if tid.Type != tt.typ {
			t.Errorf("ParseTimeId(%q).Type = %q, want %q", tt.input, tid.Type, tt.typ)
		}
		if tid.Unix != tt.unix {
			t.Errorf("ParseTimeId(%q).Unix = %d, want %d", tt.input, tid.Unix, tt.unix)
		}
		if tid.Nano != tt.nano {
			t.Errorf("ParseTimeId(%q).Nano = %d, want %d", tt.input, tid.Nano, tt.nano)
		}
		if tid.Index != tt.index {
			t.Errorf("ParseTimeId(%q).Index = %d, want %d", tt.input, tid.Index, tt.index)
		}
	}
}

func TestParseTimeIdErrors(t *testing.T) {
	_, err := ParseTimeId("invalid")
	if err == nil {
		t.Error("expected error for invalid format")
	}

	_, err = ParseTimeId("abc:def:ghi")
	if err == nil {
		t.Error("expected error for non-numeric parts")
	}
}

func TestTimeIdString(t *testing.T) {
	tid := &TimeId{Type: "tx", Unix: 1000, Nano: 500, Index: 1}
	if s := tid.String(); s != "tx:1000:500:1" {
		t.Errorf("expected tx:1000:500:1, got %s", s)
	}

	tid2 := &TimeId{Unix: 1000, Nano: 500, Index: 1}
	if s := tid2.String(); s != "nil:1000:500:1" {
		t.Errorf("expected nil:1000:500:1, got %s", s)
	}
}

func TestTimeIdTime(t *testing.T) {
	tid := &TimeId{Unix: 1700000000, Nano: 500}
	tm := tid.Time()
	if tm.Unix() != 1700000000 {
		t.Errorf("expected unix 1700000000, got %d", tm.Unix())
	}
	if tm.Nanosecond() != 500 {
		t.Errorf("expected nano 500, got %d", tm.Nanosecond())
	}
}

func TestTimeIdJSON(t *testing.T) {
	tid := &TimeId{Type: "tx", Unix: 1000, Nano: 500, Index: 1}
	data, err := json.Marshal(tid)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	tid2 := &TimeId{}
	err = json.Unmarshal(data, tid2)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if tid2.Type != "tx" || tid2.Unix != 1000 || tid2.Nano != 500 || tid2.Index != 1 {
		t.Errorf("round-trip failed: got %+v", tid2)
	}
}

func TestTimeIdUnmarshalJSONErrors(t *testing.T) {
	tid := &TimeId{}
	err := json.Unmarshal([]byte(`123`), tid)
	if err == nil {
		t.Error("expected error for non-string JSON")
	}

	err = json.Unmarshal([]byte(`"invalid"`), tid)
	if err == nil {
		t.Error("expected error for invalid format")
	}

	err = json.Unmarshal([]byte(`"abc:def:ghi"`), tid)
	if err == nil {
		t.Error("expected error for non-numeric parts")
	}
}

func TestTimeIdBinary(t *testing.T) {
	tid := &TimeId{Unix: 1700000000, Nano: 500, Index: 3}
	data, err := tid.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal binary error: %v", err)
	}
	if len(data) != TimeIdDataLen {
		t.Errorf("expected %d bytes, got %d", TimeIdDataLen, len(data))
	}

	tid2 := &TimeId{}
	err = tid2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("unmarshal binary error: %v", err)
	}
	if tid2.Unix != 1700000000 || tid2.Nano != 500 || tid2.Index != 3 {
		t.Errorf("round-trip failed: got %+v", tid2)
	}
}

func TestTimeIdUnmarshalBinaryError(t *testing.T) {
	tid := &TimeId{}
	err := tid.UnmarshalBinary([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for bad data length")
	}
}

func TestTimeIdBytes(t *testing.T) {
	tid := &TimeId{Unix: 100, Nano: 200, Index: 300}
	buf := tid.Bytes(nil)
	if len(buf) != TimeIdDataLen {
		t.Errorf("expected %d bytes, got %d", TimeIdDataLen, len(buf))
	}

	// Test with pre-existing buffer
	pre := []byte{0xFF}
	buf2 := tid.Bytes(pre)
	if buf2[0] != 0xFF {
		t.Error("expected prefix byte preserved")
	}
	if len(buf2) != TimeIdDataLen+1 {
		t.Errorf("expected %d bytes, got %d", TimeIdDataLen+1, len(buf2))
	}
}

func TestTimeIdCmp(t *testing.T) {
	a := TimeId{Unix: 100, Nano: 200, Index: 1}
	b := TimeId{Unix: 100, Nano: 200, Index: 1}
	if a.Cmp(b) != 0 {
		t.Error("equal ids should return 0")
	}

	// Different unix
	c := TimeId{Unix: 200, Nano: 0, Index: 0}
	if a.Cmp(c) != -1 {
		t.Error("expected -1 for lower unix")
	}
	if c.Cmp(a) != 1 {
		t.Error("expected 1 for higher unix")
	}

	// Same unix, different nano
	d := TimeId{Unix: 100, Nano: 300, Index: 1}
	if a.Cmp(d) != -1 {
		t.Error("expected -1 for lower nano")
	}
	if d.Cmp(a) != 1 {
		t.Error("expected 1 for higher nano")
	}

	// Same unix+nano, different index
	e := TimeId{Unix: 100, Nano: 200, Index: 5}
	if a.Cmp(e) != -1 {
		t.Error("expected -1 for lower index")
	}
	if e.Cmp(a) != 1 {
		t.Error("expected 1 for higher index")
	}
}

func TestTimeIdUnique(t *testing.T) {
	u := &TimeIdUnique{}

	t1 := &TimeId{Unix: 100, Nano: 500, Index: 0}
	u.Unique(t1)

	// Same time → should increment index
	t2 := &TimeId{Unix: 100, Nano: 500, Index: 0}
	u.Unique(t2)
	if t2.Index != 1 {
		t.Errorf("expected index=1, got %d", t2.Index)
	}

	// Earlier time → should still advance
	t3 := &TimeId{Unix: 50, Nano: 0, Index: 0}
	u.Unique(t3)
	if t3.Index != 2 {
		t.Errorf("expected index to advance, got %d", t3.Index)
	}

	// Later time → should just take it
	t4 := &TimeId{Unix: 200, Nano: 0, Index: 0}
	u.Unique(t4)
	if t4.Unix != 200 {
		t.Errorf("expected unix=200, got %d", t4.Unix)
	}

	// Same unix, higher nano
	t5 := &TimeId{Unix: 200, Nano: 100, Index: 0}
	u.Unique(t5)
	if t5.Nano != 100 {
		t.Errorf("expected nano=100, got %d", t5.Nano)
	}

	// Same unix, same nano, higher index
	t6 := &TimeId{Unix: 200, Nano: 100, Index: 5}
	u.Unique(t6)
	if t6.Index != 5 {
		t.Errorf("expected index=5, got %d", t6.Index)
	}
}

func TestTimeIdUniqueNew(t *testing.T) {
	u := &TimeIdUnique{}
	t1 := u.New()
	t2 := u.New()
	if t1.Cmp(*t2) >= 0 {
		t.Error("New() should return monotonically increasing ids")
	}
}
