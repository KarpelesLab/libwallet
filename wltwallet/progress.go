package wltwallet

import (
	"context"

	"github.com/KarpelesLab/apirouter"
)

// progressScope represents a contiguous sub-range of an overall 0..1 progress
// counter. Callers build a tree of scopes so each phase (per-key pre-param
// generation, final keygen, etc.) can report its local fraction without
// having to know the outer total. Reporting 0.5 on a scope with base=0.33
// and span=0.33 emits overall progress 0.495.
type progressScope struct {
	ctx        context.Context
	base, span float64
}

// newProgressScope returns the root scope spanning the full [0, 1] range.
func newProgressScope(ctx context.Context) progressScope {
	return progressScope{ctx: ctx, base: 0, span: 1}
}

// sub returns a sub-scope that covers the idx-th slice of total equal slices
// within this scope.
func (p progressScope) sub(idx, total int) progressScope {
	if total <= 0 {
		return p
	}
	s := p.span / float64(total)
	return progressScope{ctx: p.ctx, base: p.base + s*float64(idx), span: s}
}

// report emits a progress event at local fraction frac (clamped to [0, 1])
// translated into this scope's absolute range.
func (p progressScope) report(frac float64) {
	if frac < 0 {
		frac = 0
	} else if frac > 1 {
		frac = 1
	}
	apirouter.Progress(p.ctx, map[string]any{"progress": p.base + p.span*frac})
}
