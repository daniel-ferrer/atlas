package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
)

type Unit struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Active      string  `json:"active"`
	Sub         string  `json:"sub"`
	Since       *int64  `json:"since"`
	MemBytes    *uint64 `json:"memBytes"`
}

type UnitsResult struct {
	Units   []Unit `json:"units"`
	Warning string `json:"warning,omitempty"`
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

func execCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

func Units(ctx context.Context) UnitsResult { return collectUnits(ctx, execCommand) }

func collectUnits(ctx context.Context, run commandRunner) UnitsResult {
	raw, err := run(ctx, "systemctl", "list-units", "--type=service", "--all", "--output=json", "--no-pager")
	if err != nil {
		return UnitsResult{Units: []Unit{}, Warning: warningFor(err, "systemctl", "systemd units unavailable — check systemctl access")}
	}
	units, err := parseListUnits(raw)
	if err != nil {
		return UnitsResult{Units: []Unit{}, Warning: "systemctl returned invalid JSON"}
	}
	for start := 0; start < len(units); start += 100 {
		end := min(start+100, len(units))
		args := []string{"show"}
		for _, unit := range units[start:end] {
			args = append(args, unit.Name)
		}
		args = append(args, "--timestamp=unix", "--no-pager", "--property=Id,ActiveEnterTimestamp,MemoryCurrent")
		if details, showErr := run(ctx, "systemctl", args...); showErr == nil {
			mergeUnitDetails(units, parseShowBlocks(details))
		}
	}
	return UnitsResult{Units: units}
}

func parseListUnits(raw []byte) ([]Unit, error) {
	var rows []struct{ Unit, Description, Active, Sub string }
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	out := make([]Unit, 0, len(rows))
	for _, r := range rows {
		out = append(out, Unit{Name: r.Unit, Description: r.Description, Active: r.Active, Sub: r.Sub})
	}
	return out, nil
}

type unitDetail struct {
	since  *int64
	memory *uint64
}

func parseShowBlocks(raw []byte) map[string]unitDetail {
	out := map[string]unitDetail{}
	for _, block := range bytes.Split(bytes.TrimSpace(raw), []byte("\n\n")) {
		vals := map[string]string{}
		for _, line := range strings.Split(string(block), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				vals[k] = v
			}
		}
		if vals["Id"] == "" {
			continue
		}
		var d unitDetail
		if value := strings.TrimPrefix(vals["ActiveEnterTimestamp"], "@"); value != "" {
			if sec, err := strconv.ParseInt(value, 10, 64); err == nil {
				ms := sec * 1000
				d.since = &ms
			}
		}
		if value := vals["MemoryCurrent"]; value != "" && value != "[not set]" {
			if n, err := strconv.ParseUint(value, 10, 64); err == nil && n != ^uint64(0) {
				d.memory = &n
			}
		}
		out[vals["Id"]] = d
	}
	return out
}

func mergeUnitDetails(units []Unit, details map[string]unitDetail) {
	for i := range units {
		if d, ok := details[units[i].Name]; ok {
			units[i].Since, units[i].MemBytes = d.since, d.memory
		}
	}
}
