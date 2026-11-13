// Command maintenance-server is deliberately a black hole: it serves one embedded
// page and contains no router, redirect, proxy, upstream, or outbound network path.
package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed coming-soon.html maintenance.html
var pages embed.FS

func selectedPage() (string, []byte, error) {
	name := "coming-soon"
	filename := "coming-soon.html"
	switch os.Getenv("MAINT_PAGE") {
	case "maintenance":
		name = "maintenance"
		filename = "maintenance.html"
	case "coming-soon":
		// Keep the defaults.
	}
	page, err := pages.ReadFile(filename)
	if err != nil {
		return "", nil, fmt.Errorf("read embedded maintenance page: %w", err)
	}
	return name, page, nil
}

func retryAfter() string {
	value := os.Getenv("MAINT_RETRY_AFTER")
	if value == "" {
		return "3600"
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return "3600"
	}
	return strconv.Itoa(seconds)
}

func handler(page []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", retryAfter())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(page)))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method != http.MethodHead {
			_, _ = w.Write(page)
		}
	})
}

func listenAddress() (string, error) {
	addr := os.Getenv("MAINT_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8081"
	}
	colon := strings.LastIndexByte(addr, ':')
	if colon < 1 || colon == len(addr)-1 {
		return "", fmt.Errorf("MAINT_ADDR must contain an explicit host and port")
	}
	host := strings.Trim(addr[:colon], "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "", fmt.Errorf("MAINT_ADDR wildcard host is forbidden")
	}
	port, err := strconv.Atoi(addr[colon+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("MAINT_ADDR has an invalid port")
	}
	return addr, nil
}

func main() {
	addr, err := listenAddress()
	if err != nil {
		log.Fatal(err)
	}
	pageName, page, err := selectedPage()
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:                         addr,
		Handler:                      handler(page),
		ReadHeaderTimeout:            5 * time.Second,
		ReadTimeout:                  15 * time.Second,
		WriteTimeout:                 15 * time.Second,
		IdleTimeout:                  60 * time.Second,
		DisableGeneralOptionsHandler: true,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()

	log.Printf("maintenance server listening on %s, serving page %s", addr, pageName)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
