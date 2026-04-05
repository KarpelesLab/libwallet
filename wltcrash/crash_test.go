package wltcrash

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestLogNilPanic(t *testing.T) {
	// Log with nil panic should return a valid UUID without error
	id := Log(context.Background(), nil, "test")
	if id == uuid.Nil {
		t.Error("expected non-nil UUID even for nil panic")
	}
}

func TestLogNilEnv(t *testing.T) {
	// Log with non-nil panic but no env in context should return early
	id := Log(context.Background(), "test panic", "test")
	if id == uuid.Nil {
		t.Error("expected non-nil UUID")
	}
}
