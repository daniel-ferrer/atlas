package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type SmartDevice struct {
	Device       string  `json:"device"`
	Model        string  `json:"model"`
	TempC        *int    `json:"tempC"`
	WearPercent  *int    `json:"wearPercent"`
	PowerOnHours int64   `json:"powerOnHours"`
	Reallocated  int64   `json:"reallocated"`
	Written      *uint64 `json:"written"`
	State        string  `json:"state"`
}
type SmartResult struct {
	Devices []SmartDevice `json:"devices"`
	Warning string        `json:"warning,omitempty"`
}

const smartPermissionWarning = "SMART unavailable — grant CAP_SYS_RAWIO/CAP_SYS_ADMIN to the atlas unit, or a NOPASSWD sudoers entry for smartctl (requires NoNewPrivileges=false); do not run atlas as root"

func Smart(ctx context.Context) SmartResult { return collectSmart(ctx, execCommand) }
func collectSmart(ctx context.Context, run commandRunner) SmartResult {
	r := SmartResult{Devices: []SmartDevice{}}
	raw, e := run(ctx, "lsblk", "-dno", "NAME,TYPE")
	if e != nil {
		r.Warning = warningFor(e, "lsblk", "disk enumeration unavailable — install util-linux")
		return r
	}
	devs := parseLsblkDisks(raw)
	var w []string
	for _, dev := range devs {
		b, e := run(ctx, "sudo", "-n", smartctlPath(), "-j", "-a", dev)
		// execCommand uses Output, so an outer sudo failure (missing sudo,
		// denied policy, or a missing allowlisted smartctl) has no stderr here.
		// Preserve the permission warning for that graceful-degrade path.
		if (e != nil && len(strings.TrimSpace(string(b))) == 0) || smartPermissionDenied(b, e) {
			w = append(w, smartPermissionWarning)
			continue
		}
		d, pe := parseSmartctl(b)
		if pe == nil {
			d.Device = dev
			r.Devices = append(r.Devices, d)
			continue
		}
		if e != nil {
			w = append(w, warningFor(e, "smartctl", "SMART unavailable — install smartmontools and grant raw-device read access"))
		} else {
			w = append(w, fmt.Sprintf("smartctl returned invalid JSON for %s", dev))
		}
	}
	r.Warning = joinWarnings(w...)
	return r
}
func smartctlPath() string {
	if p, e := exec.LookPath("smartctl"); e == nil {
		return p
	}
	return "smartctl"
}
func parseLsblkDisks(raw []byte) []string {
	out := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "disk" {
			out = append(out, "/dev/"+f[0])
		}
	}
	return out
}

type smartJSON struct {
	ModelName   string `json:"model_name"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime struct {
		Hours int64 `json:"hours"`
	} `json:"power_on_time"`
	NVMe *struct {
		PercentageUsed   int    `json:"percentage_used"`
		PowerOnHours     int64  `json:"power_on_hours"`
		DataUnitsWritten uint64 `json:"data_units_written"`
		Temperature      int    `json:"temperature"`
	} `json:"nvme_smart_health_information_log"`
	ATASmartAttributes struct {
		Table []struct {
			ID    int `json:"id"`
			Value int `json:"value"`
			Raw   struct {
				Value json.RawMessage `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	Smartctl struct {
		ExitStatus int `json:"exit_status"`
		Messages   []struct {
			String string `json:"string"`
		} `json:"messages"`
	} `json:"smartctl"`
}

func parseSmartctl(raw []byte) (SmartDevice, error) {
	var j smartJSON
	if len(raw) == 0 || json.Unmarshal(raw, &j) != nil {
		return SmartDevice{}, errors.New("invalid smartctl JSON")
	}
	d := SmartDevice{Model: j.ModelName, PowerOnHours: j.PowerOnTime.Hours, State: "passed"}
	if j.Temperature.Current != 0 {
		v := j.Temperature.Current
		d.TempC = &v
	} else if j.NVMe != nil && j.NVMe.Temperature != 0 {
		v := j.NVMe.Temperature
		d.TempC = &v
	}
	if j.NVMe != nil && j.NVMe.PowerOnHours != 0 {
		d.PowerOnHours = j.NVMe.PowerOnHours
	}
	if j.NVMe != nil {
		v := j.NVMe.PercentageUsed
		d.WearPercent = &v
		vWritten := j.NVMe.DataUnitsWritten * 512000
		d.Written = &vWritten
	}
	for _, a := range j.ATASmartAttributes.Table {
		rawv := rawInt(a.Raw.Value)
		switch a.ID {
		case 5:
			d.Reallocated = rawv
		case 177, 231, 233:
			if d.WearPercent == nil && a.Value >= 0 && a.Value <= 100 {
				v := 100 - a.Value
				d.WearPercent = &v
			}
		case 241:
			if rawv > 0 {
				v := uint64(rawv) * 512
				d.Written = &v
			}
		}
	}
	if j.SmartStatus != nil && !j.SmartStatus.Passed {
		d.State = "fail"
	} else if d.Reallocated > 0 || (d.WearPercent != nil && *d.WearPercent >= 80) || (d.TempC != nil && *d.TempC >= 60) {
		d.State = "warn"
	}
	return d, nil
}
func rawInt(v json.RawMessage) int64 {
	var n int64
	if json.Unmarshal(v, &n) == nil {
		return n
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		fields := strings.Fields(s)
		if len(fields) != 0 {
			n, _ = strconv.ParseInt(fields[0], 10, 64)
		}
	}
	return n
}
func smartPermissionDenied(raw []byte, err error) bool {
	var j smartJSON
	if json.Unmarshal(raw, &j) == nil {
		if j.Smartctl.ExitStatus&2 != 0 {
			return true
		}
		for _, m := range j.Smartctl.Messages {
			s := strings.ToLower(m.String)
			if strings.Contains(s, "permission denied") || strings.Contains(s, "operation not permitted") {
				return true
			}
		}
	}
	if err != nil {
		s := strings.ToLower(err.Error())
		return strings.Contains(s, "permission denied") || strings.Contains(s, "operation not permitted")
	}
	return false
}
