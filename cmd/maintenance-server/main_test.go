package main

import (
	"bufio"
	"bytes"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEveryRequestIsBlackHoled(t *testing.T) {
	page := mustEmbeddedPage(t, "coming-soon.html")
	targets := []string{"/", "/Auth/Login", "/api/anything", "/../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "//api//x", "/health/ready", "/?next=http://evil", "/" + strings.Repeat("random-segment-", 400)}
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodHead, http.MethodOptions, http.MethodPatch, http.MethodTrace, "BREW"}
	for _, method := range methods {
		for i, target := range targets {
			t.Run(fmt.Sprintf("%s/target-%d", method, i), func(t *testing.T) {
				req := httptest.NewRequest(method, target, nil)
				rec := httptest.NewRecorder()
				handler(page).ServeHTTP(rec, req)
				if rec.Code != http.StatusServiceUnavailable {
					t.Fatalf("status = %d, want 503", rec.Code)
				}
				if got := rec.Header().Get("Location"); got != "" {
					t.Fatalf("unexpected redirect location %q", got)
				}
				seconds, err := strconv.Atoi(rec.Header().Get("Retry-After"))
				if err != nil || seconds <= 0 {
					t.Fatalf("invalid Retry-After %q", rec.Header().Get("Retry-After"))
				}
				want := page
				if method == http.MethodHead {
					want = nil
				}
				if !bytes.Equal(rec.Body.Bytes(), want) {
					t.Fatalf("body differs from maintenance page (got %d bytes, want %d)", rec.Body.Len(), len(want))
				}
				if bytes.Contains(bytes.ToLower(rec.Body.Bytes()), []byte("auth/login")) {
					t.Fatal("response contains app content")
				}
			})
		}
	}
}

func TestOverTheWire(t *testing.T) {
	page := mustEmbeddedPage(t, "coming-soon.html")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listeners unavailable in this sandbox: %v", err)
	}
	ts := httptest.NewUnstartedServer(handler(page))
	ts.Listener.Close()
	ts.Listener = listener
	ts.Config.DisableGeneralOptionsHandler = true
	ts.Start()
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "http://")
	tests := []struct{ method, target string }{{"GET", "/../etc/passwd"}, {"GET", "http://inkworx.io/Admin"}, {"OPTIONS", "*"}, {"HEAD", "/"}}
	for _, tc := range tests {
		t.Run(tc.method+"_"+strings.ReplaceAll(tc.target, "/", "_"), func(t *testing.T) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: inkworx.io\r\nConnection: close\r\n\r\n", tc.method, tc.target); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: tc.method})
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 503 {
				t.Fatalf("status = %d, want 503", resp.StatusCode)
			}
			if resp.Header.Get("Retry-After") == "" {
				t.Fatal("Retry-After missing")
			}
			if tc.method == "HEAD" && len(body) != 0 {
				t.Fatalf("HEAD body has %d bytes", len(body))
			}
			if tc.method != "HEAD" && !bytes.Equal(body, page) {
				t.Fatal("body differs from maintenance page")
			}
		})
	}
}

func TestSourceHasNoProxyMachinery(t *testing.T) {
	allowed := map[string]bool{"embed": true, "context": true, "errors": true, "fmt": true, "log": true, "net/http": true, "os": true, "os/signal": true, "strconv": true, "strings": true, "syscall": true, "time": true}
	forbiddenText := []string{"ReverseProxy", "http.Redirect", "StatusMovedPermanently", "StatusFound", "NewServeMux", `Header().Set("Location"`}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), data, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !allowed[path] {
				t.Errorf("forbidden or unexpected import %q", path)
			}
		}
		for _, needle := range forbiddenText {
			if bytes.Contains(data, []byte(needle)) {
				t.Errorf("%s contains forbidden machinery %q", entry.Name(), needle)
			}
		}
	}
}

func TestPageIsSelfContained(t *testing.T) {
	for _, filename := range []string{"coming-soon.html", "maintenance.html"} {
		t.Run(filename, func(t *testing.T) {
			lower := bytes.ToLower(mustEmbeddedPage(t, filename))
			for _, needle := range []string{"http://", "https://", "//cdn", "<script", "<form", "<img", "srcset", "@import"} {
				if bytes.Contains(lower, []byte(needle)) {
					t.Errorf("page contains external or active content %q", needle)
				}
			}
		})
	}
}

func TestSelectedPage(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv("MAINT_PAGE", "temporary-test-value")
		if err := os.Unsetenv("MAINT_PAGE"); err != nil {
			t.Fatal(err)
		}
		name, page, err := selectedPage()
		if err != nil {
			t.Fatal(err)
		}
		want := mustEmbeddedPage(t, "coming-soon.html")
		if name != "coming-soon" || !bytes.Equal(page, want) {
			t.Fatalf("unset MAINT_PAGE selected %q with expected-bytes=%t", name, bytes.Equal(page, want))
		}
	})

	tests := []struct {
		value    string
		wantName string
		wantFile string
		marker   string
	}{
		{value: "coming-soon", wantName: "coming-soon", wantFile: "coming-soon.html", marker: "InkWorx — You Found Us"},
		{value: "maintenance", wantName: "maintenance", wantFile: "maintenance.html", marker: "InkWorx — Just a Touch-Up"},
		{value: "", wantName: "coming-soon", wantFile: "coming-soon.html", marker: "InkWorx — You Found Us"},
		{value: "invalid", wantName: "coming-soon", wantFile: "coming-soon.html", marker: "InkWorx — You Found Us"},
		{value: "../secret", wantName: "coming-soon", wantFile: "coming-soon.html", marker: "InkWorx — You Found Us"},
		{value: "Coming-Soon", wantName: "coming-soon", wantFile: "coming-soon.html", marker: "InkWorx — You Found Us"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("value_%q", tc.value), func(t *testing.T) {
			t.Setenv("MAINT_PAGE", tc.value)
			name, page, err := selectedPage()
			if err != nil {
				t.Fatal(err)
			}
			if name != tc.wantName {
				t.Fatalf("selected name = %q, want %q", name, tc.wantName)
			}
			want := mustEmbeddedPage(t, tc.wantFile)
			if !bytes.Equal(page, want) {
				t.Fatalf("selected bytes differ from %s", tc.wantFile)
			}
			if !bytes.Contains(page, []byte(tc.marker)) {
				t.Fatalf("selected page does not contain marker %q", tc.marker)
			}
			rec := httptest.NewRecorder()
			handler(page).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))
			if !bytes.Equal(rec.Body.Bytes(), want) {
				t.Fatalf("served body differs from %s", tc.wantFile)
			}
		})
	}
}

func mustEmbeddedPage(t *testing.T, filename string) []byte {
	t.Helper()
	page, err := pages.ReadFile(filename)
	if err != nil {
		t.Fatalf("read embedded %s: %v", filename, err)
	}
	return page
}

func TestListenAddressRejectsWildcardBinds(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8081", "[::]:8081", ":8081", "127.0.0.1:0", "127.0.0.1:not-a-port"} {
		t.Run(addr, func(t *testing.T) {
			t.Setenv("MAINT_ADDR", addr)
			if _, err := listenAddress(); err == nil {
				t.Fatalf("listenAddress accepted unsafe or invalid address %q", addr)
			}
		})
	}
	t.Run("default", func(t *testing.T) {
		t.Setenv("MAINT_ADDR", "")
		if got, err := listenAddress(); err != nil || got != "127.0.0.1:8081" {
			t.Fatalf("listenAddress() = %q, %v", got, err)
		}
	})
}
