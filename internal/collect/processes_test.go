package collect

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCollectProcessesSortCapAndDegrade(t *testing.T) {
	now := time.Unix(200, 0)
	snaps := make([]procSnapshot, 101)
	for i := range snaps {
		snaps[i] = procSnapshot{Process: Process{Pid: int32(i), CPUPercent: float64(i)}, CreatedMS: 100000}
	}
	r := collectProcesses(context.Background(), func(context.Context) ([]procSnapshot, error) { return snaps, nil }, now)
	if r.Total != 101 || len(r.Processes) != 100 || r.Processes[0].CPUPercent != 100 || r.Processes[0].UptimeSeconds != 100 {
		t.Fatalf("unexpected result: %+v", r)
	}
	r = collectProcesses(context.Background(), func(context.Context) ([]procSnapshot, error) { return nil, errors.New("denied") }, now)
	if len(r.Processes) != 0 || r.Warning == "" {
		t.Fatalf("expected graceful degradation: %+v", r)
	}
}
