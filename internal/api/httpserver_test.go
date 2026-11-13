package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daniel-ferrer/atlas/internal/config"
	"github.com/daniel-ferrer/atlas/internal/hostops"
)

func serveSocket(t *testing.T, srv *http.Server) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close(); <-done })
	return "http://" + listener.Addr().String()
}
func TestActionReplyOutlivesHTTPTimeouts(t *testing.T) {
	s, f := fixture(t)
	f.run = func(ctx context.Context) hostops.Result {
		select {
		case <-ctx.Done():
			return hostops.Result{Unknown: true, Output: "context canceled"}
		case <-time.After(600 * time.Millisecond):
			return f.result
		}
	}
	srv := NewHTTPServer(s.cfg, s.handler())
	srv.ReadTimeout = 100 * time.Millisecond
	srv.WriteTimeout = 100 * time.Millisecond
	srv.IdleTimeout = 100 * time.Millisecond
	base := serveSocket(t, srv)
	req, err := http.NewRequest("POST", base+"/api/actions", strings.NewReader(body("restart-unit")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result actionResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !result.OK {
		t.Fatalf("%d %+v", resp.StatusCode, result)
	}
}
func TestNormalRouteStillHasWriteTimeout(t *testing.T) {
	srv := NewHTTPServer(config.Config{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond)
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	srv.ReadTimeout = 100 * time.Millisecond
	srv.WriteTimeout = 100 * time.Millisecond
	base := serveSocket(t, srv)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(base + "/normal")
	if err == nil {
		defer resp.Body.Close()
		b, readErr := io.ReadAll(resp.Body)
		if readErr == nil && string(b) == "{\"ok\":true}\n" {
			t.Fatal("slow normal route unexpectedly completed; test does not exercise write deadline")
		}
	}
}
func TestDisconnectDoesNotCancelHostAction(t *testing.T) {
	s, f := fixture(t)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.run = func(ctx context.Context) hostops.Result {
		defer close(finished)
		close(entered)
		<-release
		if ctx.Err() != nil {
			return hostops.Result{Unknown: true}
		}
		return f.result
	}
	srv := NewHTTPServer(s.cfg, s.handler())
	base := serveSocket(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", base+"/api/actions", strings.NewReader(body("restart-unit")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		resp, _ := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("action did not start")
	}
	cancel()
	<-clientDone
	close(release)
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("action did not finish")
	}
	// Shutdown waits for the handler's durable completion record as well as the op.
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelShutdown()
	if err = srv.Shutdown(shutdown); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.cfg.ActionDir, "active.json")); !os.IsNotExist(err) {
		t.Fatal("client cancellation prevented durable completion", err)
	}
	audit, err := os.ReadFile(s.cfg.AuditPath)
	if err != nil || !strings.Contains(string(audit), `"event":"action.completed"`) || !strings.Contains(string(audit), `"ok":true`) {
		t.Fatal("missing successful completion", err)
	}
}
