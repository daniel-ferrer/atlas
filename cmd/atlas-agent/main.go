package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daniel-ferrer/atlas/internal/api"
	"github.com/daniel-ferrer/atlas/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	srv := api.NewHTTPServer(cfg, api.New(cfg))
	shutdownDone := make(chan struct{})
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	go func() {
		defer close(shutdownDone)
		<-stopped
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	log.Printf("atlas agent listening on %s; enabled host actions: %v", cfg.Addr, cfg.Actions)
	for _, kind := range cfg.Actions {
		if (kind == "restart-unit" && len(cfg.RestartUnits) == 0) || (kind == "restart-container" && len(cfg.RestartContainers) == 0) || (kind == "kill-process" && len(cfg.KillUsers) == 0) {
			log.Printf("atlas: %s enabled with empty allowlist; all requests will be refused", kind)
		}
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-shutdownDone
}
