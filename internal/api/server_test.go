package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daniel-ferrer/atlas/internal/collect"
	"github.com/daniel-ferrer/atlas/internal/config"
)

func TestAuthentication(t *testing.T) {
	h := New(config.Config{Token: "secret"})
	for _, path := range []string{"/api/vitals", "/api/units", "/api/containers", "/api/journal", "/api/config?id=backup-env", "/api/processes", "/api/network", "/api/security", "/api/smart"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
}

func TestJournalValidationBehindAuth(t *testing.T) {
	h := New(config.Config{Token: "secret"})
	r := httptest.NewRequest(http.MethodGet, "/api/journal?priority=nope", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "error") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestJournalRejectsNonServiceUnit(t *testing.T) {
	h := New(config.Config{Token: "secret"})
	r := httptest.NewRequest(http.MethodGet, "/api/journal?unit=home.mount", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatal(w.Code)
	}
}

func TestConfigEndpoint(t *testing.T) {
	s := newServer(config.Config{Token: "secret"}, nil)
	calls := 0
	s.config = func(_ context.Context, src collect.ConfigSource) (collect.ConfigResult, error) {
		calls++
		if src == mustSource(t, "unit:missing.service") {
			return collect.ConfigResult{}, &collect.ConfigError{Status: 404, Reason: "unit not found"}
		}
		return collect.ConfigResult{ID: "unit:home-backup.service", Path: "/etc/systemd/system/home-backup.service", Content: "Environment=TOKEN=[REDACTED]\n", Redacted: true}, nil
	}
	get := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/config"+query, nil)
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		return w
	}
	w := get("?id=unit:home-backup.service")
	var body map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body["redacted"] != true || body["id"] != "unit:home-backup.service" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, q := range []string{"", "?id=", "?id=/etc/passwd", "?id=unit:../x.service", "?id=backup-env&id=backup-env", "?id=backup-env&path=/etc/shadow", "?id=unit:a.service;id"} {
		if w := get(q); w.Code != 400 {
			t.Errorf("%q: %d", q, w.Code)
		}
	}
	if calls != 1 {
		t.Fatalf("invalid ids reached a reader: %d", calls)
	}
	if w := get("?id=unit:missing.service"); w.Code != 404 || strings.Contains(w.Body.String(), "content") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func mustSource(t *testing.T, id string) collect.ConfigSource {
	t.Helper()
	src, err := collect.ParseConfigID(id)
	if err != nil {
		t.Fatal(err)
	}
	return src
}
