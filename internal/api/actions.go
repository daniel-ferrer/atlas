package api

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daniel-ferrer/atlas/internal/config"
	"github.com/daniel-ferrer/atlas/internal/hostops"
)

type actionResponse struct {
	ID       string `json:"id"`
	OK       bool   `json:"ok"`
	ExitCode *int   `json:"exitCode"`
	Output   string `json:"output"`
}

func budget(kind string) time.Duration {
	switch kind {
	case "apt-upgrade":
		return 29 * time.Minute
	case "kill-process":
		return 10 * time.Second
	case "run-maintenance":
		// Otto waits 15 minutes for a maintenance task; answer before it gives up.
		return 14*time.Minute + 30*time.Second
	default:
		return 85 * time.Second
	}
}
func (s *server) entry(a actionRequest, event string, extra map[string]any) error {
	e := map[string]any{"event": event, "id": a.ID, "kind": a.Kind, "target": a.Target, "command": a.Command}
	for k, v := range extra {
		e[k] = v
	}
	return s.audit.write(e)
}
func (s *server) refuse(w http.ResponseWriter, a actionRequest, status int, reason string) {
	reason = hostops.TailText(reason, 300)
	if err := s.entry(a, "action.refused", map[string]any{"detail": reason}); err != nil {
		log.Printf("atlas: refusal audit failed: %v", err)
	}
	writeJSON(w, status, map[string]string{"id": a.ID, "error": reason})
}
func (s *server) postAction(w http.ResponseWriter, r *http.Request) {
	if len(s.cfg.Actions) == 0 {
		writeJSON(w, 404, map[string]string{"error": "host control actions are disabled"})
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		s.refuse(w, actionRequest{}, 400, "invalid or oversized request body")
		return
	}
	a, err := parseAction(raw)
	if err != nil {
		s.refuse(w, a, 400, err.Error())
		return
	}
	// Extend both deadlines: net/http's background body read can otherwise cancel
	// the connection while waiting for a long action. IdleTimeout applies between
	// requests, not while this handler owns the connection.
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(31 * time.Minute)
	if err = rc.SetReadDeadline(deadline); err != nil {
		s.refuse(w, a, 422, "cannot extend action read deadline — nothing executed")
		return
	}
	if err = rc.SetWriteDeadline(deadline); err != nil {
		s.refuse(w, a, 422, "cannot extend action write deadline — nothing executed")
		return
	}
	if err = reserve(s.cfg.ActionDir, a.ID+".json", a); err != nil {
		if errors.Is(err, os.ErrExist) {
			s.refuse(w, a, 409, "request id already used")
		} else {
			s.refuse(w, a, 422, "action store unavailable — nothing executed")
		}
		return
	}
	if err = s.entry(a, "action.received", nil); err != nil {
		s.refuse(w, a, 422, "audit unavailable — nothing executed")
		return
	}
	if s.cfg.Token == "" || !slices.Contains(s.cfg.Actions, a.Kind) {
		s.refuse(w, a, 422, "action kind is disabled")
		return
	}
	if (a.Kind == "restart-unit" && (!slices.Contains(s.cfg.RestartUnits, a.unit) || config.ProtectedUnit(a.unit, s.cfg.AptUnit))) ||
		(a.Kind == "restart-container" && (!slices.Contains(s.cfg.RestartContainers, a.name) || a.name == "atlas")) ||
		(a.Kind == "kill-process" && (!slices.Contains(s.cfg.KillUsers, a.user) || a.user == "root" || a.user == "0")) {
		s.refuse(w, a, 422, "target is protected or not allowlisted")
		return
	}
	if a.canonical() != a.Command {
		s.refuse(w, a, 409, "command does not match")
		return
	}
	if !s.actionMu.TryLock() {
		s.refuse(w, a, 409, "another host action is running")
		return
	}
	defer s.actionMu.Unlock()
	// These contexts intentionally survive client disconnection. Include live
	// preflight in the total budget so Atlas answers before Otto's own timeout.
	ctx, done := context.WithTimeout(context.Background(), s.actionBudget(a.Kind))
	defer done()
	preflight, cancel := context.WithTimeout(ctx, 5*time.Second)
	prepared, status, reason := s.prepare(preflight, a)
	preflightErr := preflight.Err()
	cancel()
	if prepared != nil && prepared.close != nil {
		defer prepared.close()
	}
	if preflightErr != nil {
		s.refuse(w, a, 422, "live target check timed out — nothing executed")
		return
	}
	if status != 0 {
		s.refuse(w, a, status, reason)
		return
	}
	if err = reserve(s.cfg.ActionDir, "active.json", a); err != nil {
		if errors.Is(err, os.ErrExist) {
			s.refuse(w, a, 409, "another action is running or unresolved; inspect Atlas audit and active.json")
		} else {
			s.refuse(w, a, 422, "action store unavailable — nothing executed")
		}
		return
	}
	if err = s.entry(a, "action.executing", map[string]any{"argv": prepared.argv}); err != nil {
		if e := clearActive(s.cfg.ActionDir); e != nil {
			log.Printf("atlas: cannot clear action interlock: %v", e)
		}
		s.refuse(w, a, 422, "audit unavailable — nothing executed")
		return
	}
	// Audit fsync can take time. In particular, an existing process can exec a
	// different program without changing pid; validate again immediately before
	// signalling the already-open pidfd.
	if prepared.recheck != nil {
		status, reason = prepared.recheck(ctx)
	}
	if status != 0 || ctx.Err() != nil {
		if status == 0 {
			status, reason = 422, "action budget expired before dispatch — nothing executed"
		}
		s.refuse(w, a, status, reason)
		if err := clearActive(s.cfg.ActionDir); err != nil {
			log.Printf("atlas: cannot clear undispatched action interlock: %v", err)
		}
		return
	}
	started := time.Now()
	// Any panic from dispatch onward is ambiguous. Never return a refusal status
	// or clear the interlock when the host might already have accepted the action.
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("atlas: action %s panicked after dispatch", a.ID)
			_ = s.entry(a, "action.completed", map[string]any{"ok": false, "exitCode": nil, "unknown": true, "durationMs": time.Since(started).Milliseconds(), "output": "panic; outcome unknown"})
			writeJSON(w, 500, map[string]string{"id": a.ID, "error": "outcome unknown; inspect Atlas audit and host state"})
		}
	}()
	result := prepared.run(ctx)
	if ctx.Err() != nil {
		result.Unknown = true
		result.OK = false
		result.ExitCode = nil
	}
	if result.Unknown {
		result.OK = false
		result.ExitCode = nil
	}
	result.Output = hostops.TailText(result.Output, 4000)
	completionErr := s.entry(a, "action.completed", map[string]any{"ok": result.OK, "exitCode": result.ExitCode, "unknown": result.Unknown, "output": result.Output, "durationMs": time.Since(started).Milliseconds()})
	if completionErr != nil {
		log.Printf("atlas: COMPLETION AUDIT FAILED for %s: %v", a.ID, completionErr)
	}
	if !result.Unknown && completionErr == nil {
		if err := clearActive(s.cfg.ActionDir); err != nil {
			log.Printf("atlas: action %s completed but interlock could not be cleared: %v", a.ID, err)
		}
	}
	if result.Unknown {
		writeJSON(w, 504, map[string]string{"id": a.ID, "error": "outcome unknown; inspect Atlas audit, unit journal and host state before retrying"})
		return
	}
	writeJSON(w, 200, actionResponse{ID: a.ID, OK: result.OK, ExitCode: result.ExitCode, Output: result.Output})
}

type execution func(context.Context) hostops.Result

type preparedAction struct {
	run     execution
	argv    [][]string
	close   func()
	recheck func(context.Context) (int, string)
}

func (s *server) prepare(ctx context.Context, a actionRequest) (*preparedAction, int, string) {
	refuse := func(status int, reason string) (*preparedAction, int, string) { return nil, status, reason }
	own, err := s.ops.SelfUnits()
	if err != nil {
		return refuse(422, "cannot establish Atlas protected units")
	}
	protected := func(name string) bool { return config.ProtectedUnit(name, s.cfg.AptUnit) || slices.Contains(own, name) }
	switch a.Kind {
	case "restart-unit":
		if protected(a.unit) {
			return refuse(422, "protected unit")
		}
		unit, err := s.ops.ResolveUnit(ctx, a.unit)
		if err != nil || unit.LoadState != "loaded" {
			return refuse(422, "target no longer exists or cannot be inspected")
		}
		if unit.ID != a.unit {
			return refuse(422, "unit aliases are refused")
		}
		for _, name := range append(unit.Names, unit.ID) {
			if protected(name) {
				return refuse(422, "protected unit identity")
			}
		}
		return &preparedAction{
			run:  func(ctx context.Context) hostops.Result { return s.ops.RestartUnit(ctx, unit.ID) },
			argv: [][]string{{"systemctl", "--no-ask-password", "restart", "--", unit.ID}},
		}, 0, ""
	case "restart-container":
		c, err := s.ops.InspectContainer(ctx, a.name)
		if err != nil || c.ID == "" || c.Name != a.name {
			return refuse(422, "container no longer exists or identity changed")
		}
		if c.State != "running" && c.State != "restarting" {
			return refuse(422, "container is stopped; restart refused to preserve maintenance mode")
		}
		return &preparedAction{
			run:  func(ctx context.Context) hostops.Result { return s.ops.RestartContainer(ctx, c.ID) },
			argv: [][]string{{"docker", "restart", c.ID}},
		}, 0, ""
	case "kill-process":
		p, err := s.ops.OpenProcess(ctx, a.pid)
		if err != nil {
			return refuse(422, "cannot open stable process handle")
		}
		check := func(ctx context.Context) (int, string) { return checkProcess(ctx, p, a, protected) }
		if status, reason := check(ctx); status != 0 {
			_ = p.Close()
			return refuse(status, reason)
		}
		return &preparedAction{
			run: func(ctx context.Context) hostops.Result {
				if ctx.Err() != nil {
					return hostops.Result{Unknown: true}
				}
				if err := p.Signal(syscall.SIGTERM); err != nil {
					return hostops.Result{Output: err.Error()}
				}
				return hostops.Result{OK: true, ExitCode: hostops.Exit(0)}
			},
			argv:  [][]string{{"pidfd_send_signal", strconv.Itoa(int(a.pid)), "SIGTERM"}},
			close: func() { _ = p.Close() }, recheck: check,
		}, 0, ""
	case "apt-upgrade":
		p, err := s.ops.AptUnitInfo(ctx, s.cfg.AptUnit)
		if err != nil {
			return refuse(422, "apt unit unavailable")
		}
		if err = hostops.ValidateApt(p, s.cfg.AptUnit); err != nil {
			return refuse(422, err.Error())
		}
		if p["ActiveState"] != "inactive" && p["ActiveState"] != "failed" {
			return refuse(409, "apt unit is already active")
		}
		return &preparedAction{
			run:  func(ctx context.Context) hostops.Result { return s.ops.RunApt(ctx, s.cfg.AptUnit) },
			argv: append([][]string{{"systemctl", "--no-ask-password", "start", "--", s.cfg.AptUnit}}, hostops.AptCommands...),
		}, 0, ""
	case "run-maintenance":
		if protected(a.unit) {
			return refuse(422, "protected unit")
		}
		p, err := s.ops.UnitInfo(ctx, a.unit)
		if err != nil || p["LoadState"] != "loaded" {
			return refuse(422, "maintenance unit is not installed — nothing executed")
		}
		if p["Id"] != a.unit || strings.Join(strings.Fields(p["Names"]), " ") != a.unit {
			return refuse(422, "unit aliases are refused")
		}
		if p["Type"] != "oneshot" {
			return refuse(422, "maintenance unit is not a oneshot")
		}
		if p["ActiveState"] != "inactive" && p["ActiveState"] != "failed" {
			return refuse(409, "maintenance unit is already active")
		}
		return &preparedAction{
			run:  func(ctx context.Context) hostops.Result { return s.ops.RunMaintenance(ctx, a.unit) },
			argv: [][]string{{"systemctl", "--no-ask-password", "start", "--", a.unit}},
		}, 0, ""
	}
	return refuse(422, "unsupported action")
}

func checkProcess(ctx context.Context, p hostops.Process, a actionRequest, protected func(string) bool) (int, string) {
	identity, err := p.Identity(ctx)
	if err != nil {
		return 422, "process identity unreadable"
	}
	// Read identity between pidfd_open and a liveness probe on that handle.
	// A pid reused during the read cannot pass the probe on the old handle.
	if err = p.Signal(0); err != nil {
		return 422, "process unavailable or Atlas lacks permission to signal it"
	}
	if identity.PID != a.pid || identity.User != a.user || identity.Command != a.processCommand || identity.CreatedMS < a.startedAt-5000 || identity.CreatedMS > a.startedAt+5000 {
		return 409, "process changed"
	}
	if identity.PID <= 2 || identity.Kernel || identity.Ancestor || len(identity.UIDs) == 0 || slices.Contains(identity.UIDs, 0) {
		return 422, "protected process"
	}
	for _, unit := range identity.Cgroups {
		if protected(unit) {
			return 422, "protected process cgroup"
		}
	}
	return 0, ""
}
