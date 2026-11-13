// Package hostops implements narrowly scoped host operations. No received command
// string is ever passed to a shell or an executable.
package hostops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
)

type Unit struct {
	ID, LoadState string
	Names         []string
}
type Container struct{ ID, Name, State string }
type Identity struct {
	PID              int32
	User, Command    string
	CreatedMS        int64
	UIDs             []uint32
	Kernel, Ancestor bool
	Cgroups          []string
}
type Process interface {
	Identity(context.Context) (Identity, error)
	Signal(syscall.Signal) error
	Close() error
}
type Result struct {
	OK       bool
	ExitCode *int
	Output   string
	Unknown  bool
}
type Ops interface {
	ResolveUnit(context.Context, string) (Unit, error)
	RestartUnit(context.Context, string) Result
	InspectContainer(context.Context, string) (Container, error)
	RestartContainer(context.Context, string) Result
	OpenProcess(context.Context, int32) (Process, error)
	AptUnitInfo(context.Context, string) (map[string]string, error)
	RunApt(context.Context, string) Result
	UnitInfo(context.Context, string) (map[string]string, error)
	RunMaintenance(context.Context, string) Result
	SelfUnits() ([]string, error)
}
type Real struct{}

var AptCommands = [][]string{
	{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"},
	{"env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "upgrade"},
}

// Tail bounds memory even if a child writes indefinitely. stdout and stderr may
// write concurrently. TailText also handles a cut through a UTF-8 code point.
type Tail struct {
	mu   sync.Mutex
	data []byte
}

func (t *Tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(p)
	if n >= 65536 {
		t.data = append(t.data[:0], p[n-65536:]...)
	} else {
		if len(t.data)+n > 65536 {
			t.data = t.data[len(t.data)+n-65536:]
		}
		t.data = append(t.data, p...)
	}
	return n, nil
}
func (t *Tail) String() string { t.mu.Lock(); defer t.mu.Unlock(); return string(t.data) }
func TailText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) > limit {
		s = s[len(s)-limit:]
		for len(s) > 0 && !utf8.RuneStart(s[0]) {
			s = s[1:]
		}
	}
	return s
}
func Exit(code int) *int { return &code }
func Run(ctx context.Context, name string, args ...string) Result {
	var out Tail
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	r := Result{OK: err == nil, ExitCode: Exit(0), Output: out.String()}
	if ctx.Err() != nil || errors.Is(err, exec.ErrWaitDelay) {
		r.OK = false
		r.Unknown = true
		r.ExitCode = nil
	}
	if err != nil {
		r.OK = false
		var ee *exec.ExitError
		if errors.As(err, &ee) && !r.Unknown {
			if ee.ExitCode() < 0 {
				r.Unknown = true
				r.ExitCode = nil
			} else {
				r.ExitCode = Exit(ee.ExitCode())
			}
		} else {
			r.ExitCode = nil
		}
		r.Output += "\n" + err.Error()
	}
	return r
}

// Properties parses systemctl show output. Repeated keys are kept in order,
// joined by newlines: systemctl prints one ExecStart= line per command.
func Properties(text string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			if prev, seen := result[k]; seen {
				v = prev + "\n" + v
			}
			result[k] = v
		}
	}
	return result
}
func show(ctx context.Context, unit, props string) (map[string]string, error) {
	r := Run(ctx, "systemctl", "show", "--property="+props, "--", unit)
	if !r.OK {
		return nil, errors.New("unable to inspect systemd unit")
	}
	return Properties(r.Output), nil
}
func (Real) ResolveUnit(ctx context.Context, name string) (Unit, error) {
	p, err := show(ctx, name, "Id,Names,LoadState")
	return Unit{ID: p["Id"], Names: strings.Fields(p["Names"]), LoadState: p["LoadState"]}, err
}
func (Real) RestartUnit(ctx context.Context, name string) Result {
	return Run(ctx, "systemctl", "--no-ask-password", "restart", "--", name)
}
func dockerClient() (*client.Client, error) {
	// Always use the local daemon; DOCKER_HOST must not redirect host actions.
	return client.NewClientWithOpts(client.WithHost("unix:///var/run/docker.sock"), client.WithAPIVersionNegotiation())
}
func (Real) InspectContainer(ctx context.Context, name string) (Container, error) {
	c, err := dockerClient()
	if err != nil {
		return Container{}, err
	}
	defer c.Close()
	info, err := c.ContainerInspect(ctx, name)
	if err != nil {
		return Container{}, err
	}
	if info.ContainerJSONBase == nil || info.State == nil {
		return Container{}, errors.New("container identity unavailable")
	}
	return Container{ID: info.ID, Name: strings.TrimPrefix(info.Name, "/"), State: info.State.Status}, nil
}
func (Real) RestartContainer(ctx context.Context, id string) Result {
	c, err := dockerClient()
	if err != nil {
		return Result{Output: err.Error()}
	}
	defer c.Close()
	err = c.ContainerRestart(ctx, id, container.StopOptions{})
	if err != nil {
		// Transport failures may have happened after Docker accepted the restart.
		return Result{Output: err.Error(), Unknown: !client.IsErrNotFound(err) && !errdefs.IsInvalidParameter(err) && !errdefs.IsForbidden(err) && !errdefs.IsUnauthorized(err)}
	}
	return Result{OK: true, ExitCode: Exit(0)}
}
func (Real) AptUnitInfo(ctx context.Context, unit string) (map[string]string, error) {
	return show(ctx, unit, "Id,LoadState,ActiveState,Type,User,RemainAfterExit,ExecStart,ExecStartPre,ExecStartPost,ExecCondition,ExecStop,ExecStopPost,Environment,EnvironmentFiles")
}

// ValidateApt refuses drift, including additional hooks and environment sources.
// systemctl renders each command as { path=... ; argv[]=... ; ... }. Reject
// alternate escaping, prefixes and ignore_errors, rather than interpreting them.
func ValidateApt(p map[string]string, unit string) error {
	if p["Id"] != unit || p["LoadState"] != "loaded" || p["Type"] != "oneshot" || (p["User"] != "" && p["User"] != "root") || p["RemainAfterExit"] != "no" {
		return errors.New("apt unit identity or type differs from reviewed unit")
	}
	for _, key := range []string{"ExecStartPre", "ExecStartPost", "ExecCondition", "ExecStop", "ExecStopPost", "EnvironmentFiles"} {
		if p[key] != "" {
			return fmt.Errorf("apt unit has unexpected %s", key)
		}
	}
	if p["Environment"] != "DEBIAN_FRONTEND=noninteractive" {
		return errors.New("apt environment differs from reviewed unit")
	}
	commands, err := ExecArgv(p["ExecStart"])
	if err != nil || len(commands) != 2 {
		return errors.New("apt commands differ from reviewed unit")
	}
	for i, argv := range commands {
		if len(argv) == 0 || filepath.Base(argv[0]) != "apt-get" || !slices.Equal(argv[1:], AptCommands[i][3:]) {
			return errors.New("apt commands differ from reviewed unit")
		}
	}
	return nil
}

// ExecArgv parses one rendered command per line, as joined by Properties.
func ExecArgv(s string) ([][]string, error) {
	var result [][]string
	if s == "" {
		return nil, nil
	}
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "{ ") || !strings.HasSuffix(line, " }") || strings.Count(line, " }") != 1 {
			return nil, errors.New("invalid ExecStart")
		}
		var path, argv string
		safe := false
		for _, field := range strings.Split(line[2:len(line)-2], " ; ") {
			k, v, _ := strings.Cut(field, "=")
			switch k {
			case "path":
				path = v
			case "argv[]":
				argv = v
			case "ignore_errors":
				safe = v == "no"
			}
		}
		args := strings.Fields(argv)
		if !safe || len(args) == 0 || args[0] != path || path != "/usr/bin/apt-get" || strings.ContainsAny(argv, "\\\"'\r") {
			return nil, errors.New("unreviewed ExecStart")
		}
		result = append(result, args)
	}
	return result, nil
}

// UnitInfo reads the identity and state a maintenance oneshot must have.
func (Real) UnitInfo(ctx context.Context, unit string) (map[string]string, error) {
	return show(ctx, unit, "Id,Names,LoadState,ActiveState,Type")
}
func (Real) RunApt(ctx context.Context, unit string) Result { return runOneshot(ctx, unit, "apt") }
func (Real) RunMaintenance(ctx context.Context, unit string) Result {
	return runOneshot(ctx, unit, "maintenance")
}

// runOneshot starts a oneshot unit, which blocks until it exits, then reports
// that invocation's result and journal.
func runOneshot(ctx context.Context, unit, what string) Result {
	start := Run(ctx, "systemctl", "--no-ask-password", "start", "--", unit)
	if start.Unknown {
		return start
	}
	p, err := show(ctx, unit, "InvocationID,Result,ExecMainStatus,ActiveState")
	if err != nil {
		return Result{Unknown: true, Output: start.Output + "\nunable to read " + what + " outcome"}
	}
	// A failed start can leave status from an earlier invocation. Never promote it
	// to success; preserve the start failure alongside the journal.
	code, err := strconv.Atoi(p["ExecMainStatus"])
	if err != nil || p["ActiveState"] == "activating" {
		return Result{Unknown: true, Output: what + " outcome unavailable; inspect unit journal"}
	}
	output := start.Output
	id := p["InvocationID"]
	if len(id) == 32 && strings.Trim(id, "0123456789abcdef") == "" {
		journal := Run(ctx, "journalctl", "_SYSTEMD_INVOCATION_ID="+id, "-o", "cat", "--no-pager", "-n", "400")
		output += "\n" + journal.Output
	}
	exitCode := Exit(code)
	if !start.OK && code == 0 {
		exitCode = start.ExitCode
	}
	return Result{OK: start.OK && p["Result"] == "success" && code == 0, ExitCode: exitCode, Output: output}
}
func CgroupUnits(text string) []string {
	var units []string
	for _, line := range strings.Split(text, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, segment := range strings.Split(parts[2], "/") {
			if strings.HasSuffix(segment, ".service") {
				units = append(units, segment)
			}
		}
	}
	return units
}
func (Real) SelfUnits() ([]string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}
	return CgroupUnits(string(b)), nil
}
