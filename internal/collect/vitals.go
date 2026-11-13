// Package collect gathers host telemetry via gopsutil. Each function returns a plain
// struct shaped for the Atlas API, so the HTTP layer just serialises it. This is the
// "glue mature libraries, don't parse /proc by hand" half of the agent.
package collect

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	psnet "github.com/shirou/gopsutil/v4/net"
)

// VitalsResult is the payload for GET /api/vitals.
type VitalsResult struct {
	Host   HostInfo    `json:"host"`
	CPU    CPUInfo     `json:"cpu"`
	Memory MemoryInfo  `json:"memory"`
	Disks  []MountInfo `json:"disks"`
	Net    NetInfo     `json:"net"`
}

type HostInfo struct {
	Hostname      string `json:"hostname"`
	UptimeSeconds uint64 `json:"uptimeSeconds"`
	Platform      string `json:"platform"`
	KernelVersion string `json:"kernelVersion"`
}

type CPUInfo struct {
	UsedPercent float64 `json:"usedPercent"`
	Cores       int     `json:"cores"`
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
}

type MemoryInfo struct {
	TotalBytes  uint64  `json:"totalBytes"`
	UsedBytes   uint64  `json:"usedBytes"`
	CachedBytes uint64  `json:"cachedBytes"`
	UsedPercent float64 `json:"usedPercent"`
	SwapTotal   uint64  `json:"swapTotalBytes"`
	SwapUsed    uint64  `json:"swapUsedBytes"`
}

type MountInfo struct {
	Path        string  `json:"path"`
	Device      string  `json:"device"`
	Fstype      string  `json:"fstype"`
	TotalBytes  uint64  `json:"totalBytes"`
	UsedBytes   uint64  `json:"usedBytes"`
	UsedPercent float64 `json:"usedPercent"`
}

type NetInfo struct {
	BytesRecv uint64 `json:"bytesRecv"`
	BytesSent uint64 `json:"bytesSent"`
}

// Vitals samples the current host state. CPU is measured over a short window so a single
// call returns a real utilisation figure rather than zero.
func Vitals(ctx context.Context) (VitalsResult, error) {
	var out VitalsResult

	if hi, err := host.InfoWithContext(ctx); err == nil {
		out.Host = HostInfo{
			Hostname:      hi.Hostname,
			UptimeSeconds: hi.Uptime,
			Platform:      hi.Platform,
			KernelVersion: hi.KernelVersion,
		}
	}

	if pcts, err := cpu.PercentWithContext(ctx, 150*time.Millisecond, false); err == nil && len(pcts) > 0 {
		out.CPU.UsedPercent = pcts[0]
	}
	if n, err := cpu.CountsWithContext(ctx, true); err == nil {
		out.CPU.Cores = n
	}
	if la, err := load.AvgWithContext(ctx); err == nil {
		out.CPU.Load1, out.CPU.Load5, out.CPU.Load15 = la.Load1, la.Load5, la.Load15
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		out.Memory.TotalBytes = vm.Total
		out.Memory.UsedBytes = vm.Used
		out.Memory.CachedBytes = vm.Cached
		out.Memory.UsedPercent = vm.UsedPercent
	}
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil {
		out.Memory.SwapTotal, out.Memory.SwapUsed = sw.Total, sw.Used
	}

	if parts, err := disk.PartitionsWithContext(ctx, false); err == nil {
		for _, p := range parts {
			u, err := disk.UsageWithContext(ctx, p.Mountpoint)
			if err != nil || u == nil || u.Total == 0 {
				continue
			}
			out.Disks = append(out.Disks, MountInfo{
				Path:        p.Mountpoint,
				Device:      p.Device,
				Fstype:      u.Fstype,
				TotalBytes:  u.Total,
				UsedBytes:   u.Used,
				UsedPercent: u.UsedPercent,
			})
		}
	}

	if io, err := psnet.IOCountersWithContext(ctx, false); err == nil && len(io) > 0 {
		out.Net = NetInfo{BytesRecv: io[0].BytesRecv, BytesSent: io[0].BytesSent}
	}

	return out, nil
}
