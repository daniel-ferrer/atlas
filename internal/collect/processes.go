package collect

import (
	"context"
	"errors"
	"log"
	"sort"
	"strconv"
	"time"

	ps "github.com/shirou/gopsutil/v4/process"
)

type Process struct {
	Pid           int32   `json:"pid"`
	User          string  `json:"user"`
	CPUPercent    float64 `json:"cpuPercent"`
	MemPercent    float64 `json:"memPercent"`
	RSSBytes      uint64  `json:"rssBytes"`
	UptimeSeconds int64   `json:"uptimeSeconds"`
	Command       string  `json:"command"`
}
type ProcessesResult struct {
	Processes []Process `json:"processes"`
	Total     int       `json:"total"`
	Warning   string    `json:"warning,omitempty"`
}
type procSnapshot struct {
	Process
	CreatedMS int64
}
type procLister func(context.Context) ([]procSnapshot, error)

func Processes(ctx context.Context) ProcessesResult {
	return collectProcesses(ctx, listProcesses, time.Now())
}
func collectProcesses(ctx context.Context, list procLister, now time.Time) ProcessesResult {
	snaps, err := list(ctx)
	if err != nil {
		return ProcessesResult{Processes: []Process{}, Warning: warningFor(err, "process table", "process table unavailable — grant the atlas user permission to read /proc")}
	}
	items := make([]Process, 0, len(snaps))
	for _, s := range snaps {
		p := s.Process
		p.UptimeSeconds = max(0, now.Unix()-s.CreatedMS/1000)
		items = append(items, p)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].CPUPercent > items[j].CPUPercent })
	total := len(items)
	if total > 100 {
		log.Printf("process collector truncated %d processes to 100", total)
		items = items[:100]
	}
	return ProcessesResult{Processes: items, Total: total}
}
func listProcesses(ctx context.Context) ([]procSnapshot, error) {
	procs, err := ps.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range procs {
		_, _ = p.PercentWithContext(ctx, 0)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(250 * time.Millisecond):
	}
	out := make([]procSnapshot, 0, len(procs))
	for _, p := range procs {
		cpu, e := p.PercentWithContext(ctx, 0)
		if e != nil {
			cpu, e = p.CPUPercentWithContext(ctx)
		}
		if e != nil {
			continue
		}
		mem, e := p.MemoryPercentWithContext(ctx)
		if e != nil {
			continue
		}
		mi, e := p.MemoryInfoWithContext(ctx)
		if e != nil {
			continue
		}
		user, cmd, created, e := ProcessIdentity(ctx, p)
		if e != nil {
			continue
		}
		out = append(out, procSnapshot{Process: Process{Pid: p.Pid, User: user, CPUPercent: cpu, MemPercent: float64(mem), RSSBytes: mi.RSS, Command: cmd}, CreatedMS: created})
	}
	if len(procs) > 0 && len(out) == 0 {
		return nil, errors.New("permission denied reading process details")
	}
	return out, nil
}

// ProcessIdentity is shared by telemetry and action validation. Keep the fallback
// semantics identical: Otto sends these exact strings back when approving SIGTERM.
func ProcessIdentity(ctx context.Context, p *ps.Process) (user, command string, createdMS int64, err error) {
	createdMS, err = p.CreateTimeWithContext(ctx)
	if err != nil {
		return
	}
	user, _ = p.UsernameWithContext(ctx)
	if user == "" {
		if ids, e := p.UidsWithContext(ctx); e == nil && len(ids) != 0 {
			user = strconv.FormatInt(int64(ids[0]), 10)
		}
	}
	command, _ = p.CmdlineWithContext(ctx)
	if command == "" {
		command, _ = p.NameWithContext(ctx)
	}
	return
}
