package collect

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type ContainerPort struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort uint16 `json:"privatePort"`
	PublicPort  uint16 `json:"publicPort,omitempty"`
	Type        string `json:"type"`
}
type Container struct {
	Name          string          `json:"name"`
	Image         string          `json:"image"`
	State         string          `json:"state"`
	Status        string          `json:"status"`
	CPUPercent    float64         `json:"cpuPercent"`
	MemBytes      uint64          `json:"memBytes"`
	MemLimitBytes uint64          `json:"memLimitBytes"`
	Ports         []ContainerPort `json:"ports"`
	UptimeSeconds int64           `json:"uptimeSeconds"`
	RestartCount  int             `json:"restartCount"`
	ExitCode      int             `json:"exitCode"`
}
type ContainersResult struct {
	Containers []Container `json:"containers"`
	Warning    string      `json:"warning,omitempty"`
}

type dockerAPI interface {
	ContainerList(context.Context, containertypes.ListOptions) ([]containertypes.Summary, error)
	ContainerInspect(context.Context, string) (containertypes.InspectResponse, error)
	ContainerStats(context.Context, string, bool) (containertypes.StatsResponseReader, error)
}

func Containers(ctx context.Context) ContainersResult {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ContainersResult{Containers: []Container{}, Warning: warningFor(err, "docker", "docker socket not accessible — add the atlas user to the docker group")}
	}
	defer cli.Close()
	return collectContainers(ctx, cli, time.Now())
}

func collectContainers(ctx context.Context, api dockerAPI, now time.Time) ContainersResult {
	summaries, err := api.ContainerList(ctx, containertypes.ListOptions{All: true})
	if err != nil {
		return ContainersResult{Containers: []Container{}, Warning: warningFor(err, "docker", "docker socket not accessible — add the atlas user to the docker group")}
	}
	out := make([]Container, len(summaries))
	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := min(4, len(summaries))
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				s := summaries[i]
				inspect, _ := api.ContainerInspect(ctx, s.ID)
				var stats *containertypes.StatsResponse
				if s.State == "running" {
					if response, e := api.ContainerStats(ctx, s.ID, false); e == nil {
						func() {
							defer response.Body.Close()
							var decoded containertypes.StatsResponse
							if json.NewDecoder(response.Body).Decode(&decoded) == nil {
								stats = &decoded
							}
						}()
					}
				}
				out[i] = mapContainer(s, inspect, stats, now)
			}
		}()
	}
	for i := range summaries {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return ContainersResult{Containers: out}
}

func mapContainer(s containertypes.Summary, inspect containertypes.InspectResponse, stats *containertypes.StatsResponse, now time.Time) Container {
	name := strings.TrimPrefix(first(s.Names), "/")
	out := Container{Name: name, Image: s.Image, State: string(s.State), Status: s.Status, Ports: make([]ContainerPort, 0, len(s.Ports))}
	for _, p := range s.Ports {
		out.Ports = append(out.Ports, ContainerPort{IP: p.IP, PrivatePort: p.PrivatePort, PublicPort: p.PublicPort, Type: p.Type})
	}
	if inspect.ContainerJSONBase != nil {
		out.RestartCount = inspect.RestartCount
		if inspect.State != nil {
			out.ExitCode = inspect.State.ExitCode
			if inspect.State.Running {
				if started, err := time.Parse(time.RFC3339Nano, inspect.State.StartedAt); err == nil && now.After(started) {
					out.UptimeSeconds = int64(now.Sub(started).Seconds())
				}
			}
		}
	}
	if stats != nil {
		out.CPUPercent = dockerCPUPercent(stats)
		out.MemBytes = dockerMemory(stats)
		out.MemLimitBytes = stats.MemoryStats.Limit
	}
	return out
}
func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
func dockerCPUPercent(s *containertypes.StatsResponse) float64 {
	cpu, prev := s.CPUStats.CPUUsage.TotalUsage, s.PreCPUStats.CPUUsage.TotalUsage
	system, prevSystem := s.CPUStats.SystemUsage, s.PreCPUStats.SystemUsage
	if cpu <= prev || system <= prevSystem {
		return 0
	}
	n := s.CPUStats.OnlineCPUs
	if n == 0 {
		n = uint32(len(s.CPUStats.CPUUsage.PercpuUsage))
	}
	if n == 0 {
		return 0
	}
	return float64(cpu-prev) / float64(system-prevSystem) * float64(n) * 100
}
func dockerMemory(s *containertypes.StatsResponse) uint64 {
	usage := s.MemoryStats.Usage
	inactive := s.MemoryStats.Stats["inactive_file"]
	if inactive == 0 {
		inactive = s.MemoryStats.Stats["total_inactive_file"]
	}
	if inactive > usage {
		return usage
	}
	return usage - inactive
}

var _ io.Closer = (*client.Client)(nil)
