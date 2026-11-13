// Package api is the agent's HTTP surface: a tiny net/http mux (no framework), a
// constant-time bearer-token gate on everything under /api, and an audit hook that every
// future mutating handler routes through. Reads return JSON matching the Atlas design's
// API shapes (see docs/api.md as it grows).
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/daniel-ferrer/atlas/internal/collect"
	"github.com/daniel-ferrer/atlas/internal/config"
	"github.com/daniel-ferrer/atlas/internal/hostops"
)

// New builds the agent's HTTP handler.
func New(cfg config.Config) http.Handler {
	return newServer(cfg, hostops.Real{}).handler()
}

func newServer(cfg config.Config, ops hostops.Ops) *server {
	return &server{cfg: cfg, audit: newAuditor(cfg.AuditPath), ops: ops, actionBudget: budget, config: collect.Config}
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()

	// Liveness — unauthenticated on purpose so a health probe needs no secret.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Everything under /api requires the token.
	mux.Handle("POST /api/actions", s.auth(http.HandlerFunc(s.postAction)))
	mux.Handle("GET /api/vitals", s.auth(http.HandlerFunc(s.getVitals)))
	mux.Handle("GET /api/units", s.auth(http.HandlerFunc(s.getUnits)))
	mux.Handle("GET /api/containers", s.auth(http.HandlerFunc(s.getContainers)))
	mux.Handle("GET /api/journal", s.auth(http.HandlerFunc(s.getJournal)))
	mux.Handle("GET /api/config", s.auth(http.HandlerFunc(s.getConfig)))
	mux.Handle("GET /api/processes", s.auth(http.HandlerFunc(s.getProcesses)))
	mux.Handle("GET /api/network", s.auth(http.HandlerFunc(s.getNetwork)))
	mux.Handle("GET /api/security", s.auth(http.HandlerFunc(s.getSecurity)))
	mux.Handle("GET /api/smart", s.auth(http.HandlerFunc(s.getSmart)))

	return logRequests(mux)
}

func (s *server) getProcesses(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, collect.Processes(ctx))
}
func (s *server) getNetwork(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, collect.Network(ctx))
}
func (s *server) getSecurity(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, collect.Security(ctx))
}
func (s *server) getSmart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, collect.Smart(ctx))
}

func (s *server) getUnits(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, collect.Units(r.Context()))
}

func (s *server) getContainers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, collect.Containers(ctx))
}

func (s *server) getJournal(w http.ResponseWriter, r *http.Request) {
	q, err := collect.NewJournalQuery(r.URL.Query().Get("unit"), r.URL.Query().Get("priority"), r.URL.Query().Get("lines"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, collect.Journal(r.Context(), q))
}

// getConfig serves one allowlisted config source, redacted by Atlas. The id is
// never logged and no other query parameter is accepted.
func (s *server) getConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	if len(q) != 1 || len(q["id"]) != 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected exactly one id parameter"})
		return
	}
	src, err := collect.ParseConfigID(q.Get("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	result, err := s.config(ctx, src)
	if err != nil {
		status, reason := http.StatusServiceUnavailable, "config unavailable"
		var ce *collect.ConfigError
		if errors.As(err, &ce) {
			status, reason = ce.Status, ce.Reason
		}
		writeJSON(w, status, map[string]string{"id": q.Get("id"), "error": reason})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type server struct {
	cfg          config.Config
	audit        auditSink
	ops          hostops.Ops
	actionMu     sync.Mutex
	actionBudget func(string) time.Duration
	config       func(context.Context, collect.ConfigSource) (collect.ConfigResult, error)
}

func (s *server) getVitals(w http.ResponseWriter, r *http.Request) {
	v, err := collect.Vitals(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// auth is the shared constant-time bearer-token gate.
func (s *server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

// NewHTTPServer preserves the telemetry deadlines. POST /api/actions extends its
// own connection deadlines only after the bounded request body has been read.
func NewHTTPServer(cfg config.Config, handler http.Handler) *http.Server {
	return &http.Server{Addr: cfg.Addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
}
