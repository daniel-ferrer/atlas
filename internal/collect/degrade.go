package collect

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func warningFor(err error, source, accessHint string) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return source + " timed out"
	}
	if errors.Is(err, exec.ErrNotFound) {
		return source + " is not installed"
	}
	if accessHint != "" {
		return accessHint
	}
	return fmt.Sprintf("%s unavailable: %v", source, err)
}

func joinWarnings(parts ...string) string {
	var out []string
	seen := map[string]bool{}
	for _, part := range parts {
		if strings.TrimSpace(part) != "" && !seen[part] {
			out = append(out, part)
			seen[part] = true
		}
	}
	return strings.Join(out, "; ")
}

// boundedCommand runs a fixed argv like execCommand, but keeps only the last
// limit bytes of stdout so a noisy source cannot exhaust memory. Callers parse
// line-oriented output and skip the partial first line a cut leaves behind.
func boundedCommand(limit int) commandRunner {
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out := &tailBuffer{limit: limit}
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdout = out
		err := cmd.Run()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return out.data, err
	}
}

type tailBuffer struct {
	limit int
	data  []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n >= t.limit {
		t.data = append(t.data[:0], p[n-t.limit:]...)
		return n, nil
	}
	if over := len(t.data) + n - t.limit; over > 0 {
		t.data = append(t.data[:0], t.data[over:]...)
	}
	t.data = append(t.data, p...)
	return n, nil
}
