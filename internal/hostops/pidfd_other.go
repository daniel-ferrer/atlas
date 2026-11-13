//go:build !linux

package hostops

import (
	"context"
	"errors"
)

// Unsupported platforms refuse before execution; there is no unsafe numeric-pid fallback.
func (Real) OpenProcess(context.Context, int32) (Process, error) {
	return nil, errors.New("stable process handles are unsupported on this platform")
}
