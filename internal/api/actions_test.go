package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/daniel-ferrer/atlas/internal/config"
	"github.com/daniel-ferrer/atlas/internal/hostops"
)

const testID = "ha_00000000-0000-0000-0000-000000000001"
const nextID = "ha_00000000-0000-0000-0000-000000000002"

type fakeProcess struct {
	identity                 hostops.Identity
	err, probeErr, signalErr error
	signals                  int
	closed                   bool
}

func (p *fakeProcess) Identity(context.Context) (hostops.Identity, error) { return p.identity, p.err }
func (p *fakeProcess) Signal(sig syscall.Signal) error {
	if sig == 0 {
		return p.probeErr
	}
	if sig != syscall.SIGTERM {
		panic("unexpected signal")
	}
	p.signals++
	return p.signalErr
}
func (p *fakeProcess) Close() error { p.closed = true; return nil }

type fakeOps struct {
	unit      hostops.Unit
	container hostops.Container
	process   *fakeProcess
	apt       map[string]string
	maint     map[string]string
	err       error
	own       []string
	selfErr   error
	result    hostops.Result
	calls     atomic.Int32
	target    string
	run       func(context.Context) hostops.Result
}

func (f *fakeOps) SelfUnits() ([]string, error)                              { return f.own, f.selfErr }
func (f *fakeOps) ResolveUnit(context.Context, string) (hostops.Unit, error) { return f.unit, f.err }
func (f *fakeOps) InspectContainer(context.Context, string) (hostops.Container, error) {
	return f.container, f.err
}
func (f *fakeOps) OpenProcess(context.Context, int32) (hostops.Process, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.process, nil
}
func (f *fakeOps) AptUnitInfo(context.Context, string) (map[string]string, error) {
	return f.apt, f.err
}
func (f *fakeOps) UnitInfo(context.Context, string) (map[string]string, error) {
	return f.maint, f.err
}
func (f *fakeOps) RunMaintenance(ctx context.Context, target string) hostops.Result {
	return f.execute(ctx, target)
}
func (f *fakeOps) execute(ctx context.Context, target string) hostops.Result {
	f.calls.Add(1)
	f.target = target
	if f.run != nil {
		return f.run(ctx)
	}
	return f.result
}
func (f *fakeOps) RestartUnit(ctx context.Context, target string) hostops.Result {
	return f.execute(ctx, target)
}
func (f *fakeOps) RestartContainer(ctx context.Context, target string) hostops.Result {
	return f.execute(ctx, target)
}
func (f *fakeOps) RunApt(ctx context.Context, target string) hostops.Result {
	return f.execute(ctx, target)
}
func fixture(t *testing.T) (*server, *fakeOps) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Config{Token: "secret-token", AuditPath: filepath.Join(dir, "audit.log"), ActionDir: filepath.Join(dir, "actions"), AptUnit: "atlas-apt-upgrade.service", Actions: []string{"restart-unit", "restart-container", "kill-process", "apt-upgrade", "run-maintenance"}, RestartUnits: []string{"demo.service"}, RestartContainers: []string{"my_app"}, KillUsers: []string{"demo"}}
	f := &fakeOps{unit: hostops.Unit{ID: "demo.service", Names: []string{"demo.service"}, LoadState: "loaded"}, container: hostops.Container{ID: "stable-id", Name: "my_app", State: "running"}, result: hostops.Result{OK: true, ExitCode: hostops.Exit(0)}, process: &fakeProcess{identity: hostops.Identity{PID: 12345, User: "demo", Command: "sleep 100", CreatedMS: 100000, UIDs: []uint32{1000}}}, apt: map[string]string{"Id": "atlas-apt-upgrade.service", "LoadState": "loaded", "ActiveState": "inactive", "Type": "oneshot", "User": "root", "RemainAfterExit": "no", "Environment": "DEBIAN_FRONTEND=noninteractive", "ExecStart": "{ path=/usr/bin/apt-get ; argv[]=/usr/bin/apt-get update ; ignore_errors=no }\n{ path=/usr/bin/apt-get ; argv[]=/usr/bin/apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade ; ignore_errors=no }"}}
	f.maint = map[string]string{"Id": "otto-maint-backup-unlock.service", "Names": "otto-maint-backup-unlock.service", "LoadState": "loaded", "ActiveState": "inactive", "Type": "oneshot"}
	return newServer(cfg, f), f
}
func body(kind string) string {
	var target, command string
	switch kind {
	case "restart-unit":
		target = `{"unit":"demo.service"}`
		command = "systemctl restart demo.service"
	case "restart-container":
		target = `{"name":"my_app"}`
		command = "docker restart my_app"
	case "kill-process":
		target = `{"pid":12345,"user":"demo","command":"sleep 100","startedAt":100000}`
		command = "kill -TERM 12345"
	case "apt-upgrade":
		target = `{}`
		command = "env DEBIAN_FRONTEND=noninteractive apt-get update && env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade"
	case "run-maintenance":
		target = `{"task":"backup-unlock"}`
		command = "systemctl start otto-maint-backup-unlock.service"
	}
	return fmt.Sprintf(`{"id":%q,"kind":%q,"target":%s,"command":%q}`, testID, kind, target, command)
}

// The real socket test below proves deadlines; this recorder supports the same
// ResponseController API so action behaviour tests do not bypass its checks.
type deadlineRecorder struct{ *httptest.ResponseRecorder }

func (*deadlineRecorder) SetReadDeadline(time.Time) error  { return nil }
func (*deadlineRecorder) SetWriteDeadline(time.Time) error { return nil }
func request(s *server, raw string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/actions", strings.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	w := &deadlineRecorder{httptest.NewRecorder()}
	s.handler().ServeHTTP(w, r)
	return w.ResponseRecorder
}
func nothingRan(t *testing.T, f *fakeOps) {
	t.Helper()
	if f.calls.Load() != 0 || f.process.signals != 0 {
		t.Fatal("refusal executed a host mutation")
	}
}
func TestActionDisabledAndAuthentication(t *testing.T) {
	s, f := fixture(t)
	s.cfg.Actions = nil
	if w := request(s, body("restart-unit")); w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, token := range []string{"", "secret-token", "Bearer wrong"} {
		r := httptest.NewRequest("POST", "/api/actions", strings.NewReader(body("restart-unit")))
		r.Header.Set("Authorization", token)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	nothingRan(t, f)
}
func TestMalformedActionsNeverExecute(t *testing.T) {
	good := body("restart-unit")
	kill := body("kill-process")
	maint := body("run-maintenance")
	cases := []string{
		strings.Replace(maint, "backup-unlock", "backup-prune", 1), strings.Replace(maint, `"task":"backup-unlock"`, `"unit":"otto-maint-backup-unlock.service"`, 1),
		strings.Replace(maint, `"task":"backup-unlock"`, `"task":"backup-unlock","unit":"x.service"`, 1), strings.Replace(maint, `"task":"backup-unlock"`, `"task":"otto-maint-backup-unlock.service"`, 1),
		strings.Replace(maint, `"task":"backup-unlock"`, `"task":""`, 1), strings.Replace(maint, `"task":"backup-unlock"`, `"task":["backup-unlock"]`, 1),
		strings.Replace(good, `"kind":`, `"extra":true,"kind":`, 1), strings.Replace(good, `"unit":"demo.service"`, `"unit":"demo.service","other":1`, 1), strings.Replace(good, `"unit":"demo.service"`, `"name":"demo.service"`, 1),
		strings.Replace(kill, `,"startedAt":100000`, "", 1), strings.Replace(kill, `"pid":12345`, `"pid":12345.1`, 1), strings.Replace(kill, `"pid":12345`, `"pid":1e4`, 1), strings.Replace(kill, `"pid":12345`, `"pid":"12345"`, 1), strings.Replace(kill, `"startedAt":100000`, `"startedAt":null`, 1),
		strings.Replace(good, testID, "../evil", 1), good + ` {}`, strings.Repeat(" ", 65537) + good, strings.Replace(good, "restart-unit", "reboot", 1), strings.Replace(good, `"target":{"unit":"demo.service"}`, `"target":null`, 1),
		strings.Replace(good, `"kind":`, `"kind":"restart-unit","kind":`, 1), strings.Replace(good, `"id":`, `"ID":`, 1), strings.Replace(good, `"unit":"demo.service"`, `"unit":"demo.service","unit":"other.service"`, 1), strings.Replace(good, "demo.service", "--bad.service", 1),
	}
	for i, raw := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			s, f := fixture(t)
			w := request(s, raw)
			if w.Code != 400 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			nothingRan(t, f)
		})
	}
}
func TestCanonicalCommandsMatchOtto(t *testing.T) {
	for _, kind := range []string{"restart-unit", "restart-container", "kill-process", "apt-upgrade", "run-maintenance"} {
		a, err := parseAction([]byte(body(kind)))
		if err != nil || a.canonical() != a.Command {
			t.Fatal(kind, a.canonical(), err)
		}
	}
	for _, unit := range []string{"nginx.service", "foo@bar.service", "foo_bar.service"} {
		a := actionRequest{Kind: "restart-unit", unit: unit}
		if a.canonical() != "systemctl restart "+unit {
			t.Fatal(a.canonical())
		}
	}
	for task, unit := range config.MaintenanceUnits {
		a, err := parseAction([]byte(strings.Replace(body("run-maintenance"), `"task":"backup-unlock"`, `"task":"`+task+`"`, 1)))
		if err != nil || a.unit != unit || a.canonical() != "systemctl start "+unit {
			t.Fatal(task, a.canonical(), err)
		}
	}
	if shellQuote("a'b") != "'a'\\''b'" {
		t.Fatal("quoting")
	}
	s, f := fixture(t)
	w := request(s, strings.Replace(body("restart-container"), "docker restart my_app", "docker restart 'my_app'", 1))
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
	nothingRan(t, f)
}
func TestStaticPolicyNeverExecutes(t *testing.T) {
	for _, unit := range []string{"otto.service", "atlas.service", "tailscaled.service", "atlas-apt-upgrade.service", "unlisted.service"} {
		t.Run(unit, func(t *testing.T) {
			s, f := fixture(t)
			if unit != "unlisted.service" {
				s.cfg.RestartUnits = append(s.cfg.RestartUnits, unit)
			}
			w := request(s, strings.ReplaceAll(body("restart-unit"), "demo.service", unit))
			if w.Code != 422 {
				t.Fatal(w.Code)
			}
			nothingRan(t, f)
		})
	}
	t.Run("protected container", func(t *testing.T) {
		s, f := fixture(t)
		s.cfg.RestartContainers = []string{"atlas"}
		if w := request(s, strings.ReplaceAll(body("restart-container"), "my_app", "atlas")); w.Code != 422 {
			t.Fatal(w.Code)
		}
		nothingRan(t, f)
	})
	t.Run("disabled kind", func(t *testing.T) {
		s, f := fixture(t)
		s.cfg.Actions = []string{"apt-upgrade"}
		if w := request(s, body("restart-unit")); w.Code != 422 {
			t.Fatal(w.Code)
		}
		nothingRan(t, f)
	})
	t.Run("maintenance disabled by default list", func(t *testing.T) {
		s, f := fixture(t)
		s.cfg.Actions = []string{"restart-unit"}
		if w := request(s, body("run-maintenance")); w.Code != 422 {
			t.Fatal(w.Code)
		}
		nothingRan(t, f)
	})
	t.Run("maintenance command mismatch", func(t *testing.T) {
		s, f := fixture(t)
		raw := strings.Replace(body("run-maintenance"), "systemctl start otto-maint-backup-unlock.service", "systemctl start otto-maint-backup-cache-dir.service", 1)
		if w := request(s, raw); w.Code != 409 {
			t.Fatal(w.Code)
		}
		nothingRan(t, f)
	})
	t.Run("no kill users", func(t *testing.T) {
		s, f := fixture(t)
		s.cfg.KillUsers = nil
		if w := request(s, body("kill-process")); w.Code != 422 {
			t.Fatal(w.Code)
		}
		nothingRan(t, f)
	})
}
func TestLiveTargetsNeverExecuteWhenUnsafe(t *testing.T) {
	cases := []struct {
		name, kind string
		alter      func(*fakeOps)
	}{
		{"alias", "restart-unit", func(f *fakeOps) { f.unit.ID = "other.service" }},
		{"protected name", "restart-unit", func(f *fakeOps) { f.unit.Names = append(f.unit.Names, "otto.service") }},
		{"not found", "restart-unit", func(f *fakeOps) { f.unit.LoadState = "not-found" }},
		{"self unit", "restart-unit", func(f *fakeOps) { f.own = []string{"demo.service"} }},
		{"self unreadable", "restart-unit", func(f *fakeOps) { f.selfErr = errors.New("unreadable") }},
		{"stopped", "restart-container", func(f *fakeOps) { f.container.State = "exited" }},
		{"container renamed", "restart-container", func(f *fakeOps) { f.container.Name = "other" }},
		{"inspect failure", "restart-container", func(f *fakeOps) { f.err = errors.New("missing") }},
		{"apt drift", "apt-upgrade", func(f *fakeOps) { f.apt["ExecStart"] = "evil" }},
		{"maintenance not installed", "run-maintenance", func(f *fakeOps) { f.maint["LoadState"] = "not-found" }},
		{"maintenance unreadable", "run-maintenance", func(f *fakeOps) { f.err = errors.New("no systemd") }},
		{"maintenance alias", "run-maintenance", func(f *fakeOps) { f.maint["Id"] = "other.service" }},
		{"maintenance extra name", "run-maintenance", func(f *fakeOps) { f.maint["Names"] += " otto.service" }},
		{"maintenance not oneshot", "run-maintenance", func(f *fakeOps) { f.maint["Type"] = "simple" }},
		{"maintenance self unit", "run-maintenance", func(f *fakeOps) { f.own = []string{"otto-maint-backup-unlock.service"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, f := fixture(t)
			tc.alter(f)
			w := request(s, body(tc.kind))
			if w.Code != 422 {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			nothingRan(t, f)
		})
	}
	t.Run("maintenance active", func(t *testing.T) {
		s, f := fixture(t)
		f.maint["ActiveState"] = "activating"
		if w := request(s, body("run-maintenance")); w.Code != 409 {
			t.Fatal(w.Code)
		}
		nothingRan(t, f)
	})
	t.Run("apt active", func(t *testing.T) {
		s, f := fixture(t)
		f.apt["ActiveState"] = "activating"
		if w := request(s, body("apt-upgrade")); w.Code != 409 {
			t.Fatal(w.Code)
		}
		nothingRan(t, f)
	})
}
func TestKillIdentityAndProtections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		alter  func(*fakeProcess)
	}{
		{"user changed", 409, func(p *fakeProcess) { p.identity.User = "other" }},
		{"command changed", 409, func(p *fakeProcess) { p.identity.Command = "other" }},
		{"time changed", 409, func(p *fakeProcess) { p.identity.CreatedMS += 5001 }},
		{"root uid", 422, func(p *fakeProcess) { p.identity.UIDs = []uint32{1000, 0} }},
		{"kernel thread", 422, func(p *fakeProcess) { p.identity.Kernel = true }},
		{"self or ancestor", 422, func(p *fakeProcess) { p.identity.Ancestor = true }},
		{"otto cgroup", 422, func(p *fakeProcess) { p.identity.Cgroups = []string{"otto.service"} }},
		{"atlas cgroup", 422, func(p *fakeProcess) { p.identity.Cgroups = []string{"atlas.service"} }},
		{"EPERM", 422, func(p *fakeProcess) { p.probeErr = syscall.EPERM }},
		{"unreadable", 422, func(p *fakeProcess) { p.err = errors.New("unreadable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f := fixture(t)
			tc.alter(f.process)
			w := request(s, body("kill-process"))
			if w.Code != tc.status {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			nothingRan(t, f)
			if !f.process.closed {
				t.Fatal("leaked pidfd")
			}
		})
	}
	t.Run("start tolerance", func(t *testing.T) {
		s, f := fixture(t)
		f.process.identity.CreatedMS += 5000
		w := request(s, body("kill-process"))
		if w.Code != 200 || f.process.signals != 1 || !f.process.closed {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
	t.Run("vanished on signal", func(t *testing.T) {
		s, f := fixture(t)
		f.process.signalErr = syscall.ESRCH
		w := request(s, body("kill-process"))
		var r actionResponse
		_ = json.Unmarshal(w.Body.Bytes(), &r)
		if w.Code != 200 || r.OK {
			t.Fatal(w.Code, w.Body)
		}
	})
}
func TestDurableIDsIncludingRefusals(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(fmt.Sprint(refused), func(t *testing.T) {
			s, f := fixture(t)
			if refused {
				s.cfg.RestartUnits = nil
			}
			w := request(s, body("restart-unit"))
			if (!refused && w.Code != 200) || (refused && w.Code != 422) {
				t.Fatal(w.Code, w.Body)
			}
			f.calls.Store(0)
			for _, server := range []*server{s, newServer(s.cfg, f)} {
				if w := request(server, body("restart-unit")); w.Code != 409 {
					t.Fatal(w.Code, w.Body)
				}
			}
			nothingRan(t, f)
		})
	}
}

type failingAudit struct {
	real  auditSink
	event string
}

func (a failingAudit) write(e map[string]any) error {
	if e["event"] == a.event {
		return errors.New("disk full")
	}
	return a.real.write(e)
}
func TestStorageAndAuditFailuresNeverExecute(t *testing.T) {
	for _, which := range []string{"store", "audit", "received", "executing"} {
		t.Run(which, func(t *testing.T) {
			s, f := fixture(t)
			switch which {
			case "store":
				s.cfg.ActionDir = filepath.Join(s.cfg.AuditPath, "child")
				if err := os.WriteFile(s.cfg.AuditPath, []byte("file"), 0600); err != nil {
					t.Fatal(err)
				}
			case "audit":
				s.audit = newAuditor(t.TempDir())
			case "received", "executing":
				s.audit = failingAudit{s.audit, "action." + which}
			}
			w := request(s, body("restart-unit"))
			if w.Code != 422 {
				t.Fatal(w.Code, w.Body)
			}
			nothingRan(t, f)
		})
	}
}
func TestCompletedActionResponsesAndAudit(t *testing.T) {
	for _, kind := range []string{"restart-unit", "restart-container", "kill-process", "apt-upgrade", "run-maintenance"} {
		for _, ok := range []bool{false, true} {
			t.Run(fmt.Sprint(kind, ok), func(t *testing.T) {
				s, f := fixture(t)
				f.result = hostops.Result{OK: ok, ExitCode: hostops.Exit(7), Output: strings.Repeat("€", 30000)}
				if ok {
					f.result.ExitCode = hostops.Exit(0)
				}
				if kind == "kill-process" && !ok {
					f.process.signalErr = syscall.EPERM
				}
				w := request(s, body(kind))
				var r actionResponse
				if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
					t.Fatal(err)
				}
				if w.Code != 200 || r.ID != testID || r.OK != ok || len(r.Output) > 4000 || !utf8.ValidString(r.Output) {
					t.Fatalf("%d %+v", w.Code, r)
				}
				if kind != "kill-process" && (r.ExitCode == nil || *r.ExitCode != *f.result.ExitCode) {
					t.Fatal("exit code lost")
				}
				if kind == "run-maintenance" && f.target != "otto-maint-backup-unlock.service" {
					t.Fatal("started the wrong unit", f.target)
				}
				if kind == "restart-container" && f.target != "stable-id" {
					t.Fatal("restarted by mutable name")
				}
				audit, err := os.ReadFile(s.cfg.AuditPath)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSpace(string(audit)), "\n")
				if len(lines) != 3 {
					t.Fatal(string(audit))
				}
				for i, event := range []string{"action.received", "action.executing", "action.completed"} {
					var e map[string]any
					if err := json.Unmarshal([]byte(lines[i]), &e); err != nil || e["event"] != event || e["id"] != testID {
						t.Fatal(lines[i], err)
					}
				}
				if strings.Contains(string(audit), s.cfg.Token) {
					t.Fatal("token logged")
				}
				if _, err := os.Stat(filepath.Join(s.cfg.ActionDir, "active.json")); !os.IsNotExist(err) {
					t.Fatal("interlock retained after known completion", err)
				}
			})
		}
	}
}
func TestSerialization(t *testing.T) {
	s, f := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.run = func(context.Context) hostops.Result { close(entered); <-release; return f.result }
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- request(s, body("restart-unit")) }()
	<-entered
	for i, srv := range []*server{s, newServer(s.cfg, f)} {
		id := fmt.Sprintf("ha_00000000-0000-0000-0000-%012d", i+2)
		w := request(srv, strings.ReplaceAll(body("restart-unit"), testID, id))
		if w.Code != 409 {
			t.Fatal(w.Code, w.Body)
		}
	}
	close(release)
	if w := <-done; w.Code != 200 {
		t.Fatal(w.Code)
	}
	if f.calls.Load() != 1 {
		t.Fatal("concurrent execution")
	}
}
func TestUnknownAndCompletionAuditFailureRetainInterlock(t *testing.T) {
	for _, which := range []string{"timeout", "panic", "completion audit"} {
		t.Run(which, func(t *testing.T) {
			s, f := fixture(t)
			status := 504
			switch which {
			case "timeout":
				f.result = hostops.Result{Unknown: true}
			case "panic":
				status = 500
				f.run = func(context.Context) hostops.Result { panic("boom") }
			case "completion audit":
				status = 200
				s.audit = failingAudit{s.audit, "action.completed"}
			}
			if w := request(s, body("restart-unit")); w.Code != status {
				t.Fatal(w.Code, w.Body)
			}
			if _, err := os.Stat(filepath.Join(s.cfg.ActionDir, "active.json")); err != nil {
				t.Fatal(err)
			}
			f.calls.Store(0)
			if w := request(newServer(s.cfg, f), strings.ReplaceAll(body("restart-unit"), testID, nextID)); w.Code != 409 {
				t.Fatal(w.Code, w.Body)
			}
			nothingRan(t, f)
		})
	}
}

type auditHook struct {
	auditSink
	afterExecuting func()
}

func (a auditHook) write(e map[string]any) error {
	if err := a.auditSink.write(e); err != nil {
		return err
	}
	if e["event"] == "action.executing" {
		a.afterExecuting()
	}
	return nil
}
func TestKillRevalidatesAfterDurableAudit(t *testing.T) {
	s, f := fixture(t)
	s.audit = auditHook{s.audit, func() { f.process.identity.Command = "new program" }}
	w := request(s, body("kill-process"))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "process changed") {
		t.Fatal(w.Code, w.Body)
	}
	nothingRan(t, f)
	if !f.process.closed {
		t.Fatal("pidfd leaked")
	}
	if _, err := os.Stat(filepath.Join(s.cfg.ActionDir, "active.json")); !os.IsNotExist(err) {
		t.Fatal("undispatched action remained active", err)
	}
}
func TestExecutionBudgetExpiryIsUnknown(t *testing.T) {
	s, f := fixture(t)
	s.actionBudget = func(string) time.Duration { return 25 * time.Millisecond }
	f.run = func(ctx context.Context) hostops.Result {
		<-ctx.Done()
		return hostops.Result{OK: true, ExitCode: hostops.Exit(0)}
	}
	w := request(s, body("restart-unit"))
	if w.Code != 504 || f.calls.Load() != 1 {
		t.Fatal(w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(s.cfg.ActionDir, "active.json")); err != nil {
		t.Fatal(err)
	}
}
func TestExpiredBudgetBeforeDispatchNeverExecutes(t *testing.T) {
	s, f := fixture(t)
	s.actionBudget = func(string) time.Duration { return 25 * time.Millisecond }
	s.audit = auditHook{s.audit, func() { time.Sleep(50 * time.Millisecond) }}
	if w := request(s, body("restart-unit")); w.Code != 422 {
		t.Fatal(w.Code, w.Body)
	}
	nothingRan(t, f)
}
func TestUnsupportedResponseDeadlinesRefuse(t *testing.T) {
	s, f := fixture(t)
	r := httptest.NewRequest("POST", "/api/actions", strings.NewReader(body("restart-unit")))
	r.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code != 422 {
		t.Fatal(w.Code, w.Body)
	}
	nothingRan(t, f)
}
