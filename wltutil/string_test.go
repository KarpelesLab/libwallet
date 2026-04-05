package wltutil

import (
	"testing"
)

func TestDecodeEVMEthCallString(t *testing.T) {
	// Build a valid eth_call response encoding "hello"
	// 32 bytes offset (0x20 = 32)
	offset := make([]byte, 32)
	offset[31] = 0x20

	// 32 bytes length (5)
	length := make([]byte, 32)
	length[31] = 5

	// "hello" padded to 32 bytes
	strData := make([]byte, 32)
	copy(strData, "hello")

	data := append(append(offset, length...), strData...)

	result, err := DecodeEVMEthCallString(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestDecodeEVMEthCallStringEmpty(t *testing.T) {
	// Empty string response
	offset := make([]byte, 32)
	offset[31] = 0x20
	length := make([]byte, 32) // length = 0

	data := append(offset, length...)

	result, err := DecodeEVMEthCallString(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestDecodeEVMEthCallStringTooShort(t *testing.T) {
	_, err := DecodeEVMEthCallString([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestDecodeEVMEthCallStringTruncated(t *testing.T) {
	// Offset
	offset := make([]byte, 32)
	offset[31] = 0x20

	// Length says 100 but we only have a few bytes after
	length := make([]byte, 32)
	length[31] = 100

	data := append(offset, length...)
	data = append(data, []byte("short")...)

	_, err := DecodeEVMEthCallString(data)
	if err == nil {
		t.Error("expected error for truncated data")
	}
}

func TestDecodeEVMEthCallStringLonger(t *testing.T) {
	// Encode "Hello, World!" (13 chars)
	offset := make([]byte, 32)
	offset[31] = 0x20

	length := make([]byte, 32)
	length[31] = 13

	strData := make([]byte, 32)
	copy(strData, "Hello, World!")

	data := append(append(offset, length...), strData...)

	result, err := DecodeEVMEthCallString(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Hello, World!" {
		t.Errorf("expected 'Hello, World!', got %q", result)
	}
}
