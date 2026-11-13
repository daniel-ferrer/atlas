package collect

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	containertypes "github.com/docker/docker/api/types/container"
)

type fakeDocker struct {
	list    []containertypes.Summary
	listErr error
	inspect containertypes.InspectResponse
	stats   string
}

func (f fakeDocker) ContainerList(context.Context, containertypes.ListOptions) ([]containertypes.Summary, error) {
	return f.list, f.listErr
}
func (f fakeDocker) ContainerInspect(context.Context, string) (containertypes.InspectResponse, error) {
	return f.inspect, nil
}
func (f fakeDocker) ContainerStats(context.Context, string, bool) (containertypes.StatsResponseReader, error) {
	return containertypes.StatsResponseReader{Body: io.NopCloser(strings.NewReader(f.stats))}, nil
}

func TestContainerMapping(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	base := &containertypes.ContainerJSONBase{RestartCount: 2, State: &containertypes.State{Running: true, ExitCode: 7, StartedAt: "2026-01-01T00:00:00Z"}}
	tests := []struct {
		name  string
		stats string
		cpu   float64
		mem   uint64
	}{
		{"cgroup v2", `{"cpu_stats":{"cpu_usage":{"total_usage":300,"percpu_usage":[1,2]},"system_cpu_usage":1000,"online_cpus":2},"precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":500},"memory_stats":{"usage":1000,"limit":2000,"stats":{"inactive_file":100}}}`, 80, 900},
		{"cgroup v1", `{"cpu_stats":{"cpu_usage":{"total_usage":300,"percpu_usage":[1]},"system_cpu_usage":1000},"precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":500},"memory_stats":{"usage":1000,"limit":2000,"stats":{"total_inactive_file":200}}}`, 40, 800},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fakeDocker{list: []containertypes.Summary{{ID: "1", Names: []string{"/web"}, Image: "nginx", State: "running", Status: "Up", Ports: []containertypes.Port{{PrivatePort: 80, PublicPort: 8080, Type: "tcp"}}}}, inspect: containertypes.InspectResponse{ContainerJSONBase: base}, stats: tt.stats}
			r := collectContainers(context.Background(), f, now)
			if len(r.Containers) != 1 {
				t.Fatal(r)
			}
			c := r.Containers[0]
			if c.Name != "web" || c.CPUPercent != tt.cpu || c.MemBytes != tt.mem || c.MemLimitBytes != 2000 || c.UptimeSeconds != 60 || c.RestartCount != 2 || c.ExitCode != 7 || len(c.Ports) != 1 {
				t.Fatalf("bad mapping: %#v", c)
			}
		})
	}
}

func TestContainerMathGuards(t *testing.T) {
	s := &containertypes.StatsResponse{}
	s.CPUStats.CPUUsage.TotalUsage = 1
	s.PreCPUStats.CPUUsage.TotalUsage = 2
	s.MemoryStats.Usage = 5
	s.MemoryStats.Stats = map[string]uint64{"inactive_file": 10}
	if dockerCPUPercent(s) != 0 || dockerMemory(s) != 5 {
		t.Fatal("underflow guard failed")
	}
}

func TestContainersDegrade(t *testing.T) {
	r := collectContainers(context.Background(), fakeDocker{listErr: errors.New("denied")}, time.Now())
	if r.Containers == nil || r.Warning == "" {
		t.Fatalf("bad degradation: %#v", r)
	}
}
