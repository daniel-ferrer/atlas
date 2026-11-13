// Package config loads the agent's runtime configuration from the environment.
//
// Security-relevant defaults live here so they are visible in one place: the agent binds
// to loopback unless told otherwise, and it refuses to start without a token (a host agent
// with no auth is a foothold, not a feature). The systemd unit sets ATLAS_ADDR to the
// tailnet address and ATLAS_TOKEN to a secret.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Config is the agent's fully-resolved runtime configuration.
type Config struct {
	// Addr is the host:port to bind. Defaults to loopback so an unconfigured agent is
	// never accidentally exposed on all interfaces.
	Addr string
	// Token is the bearer token required on every /api request.
	Token string
	// AuditPath is where mutating calls are appended, one JSON object per line.
	AuditPath         string
	Actions           []string
	RestartUnits      []string
	RestartContainers []string
	KillUsers         []string
	AptUnit           string
	ActionDir         string
}

var UnitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,240}\.service$`)
var ContainerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func KnownAction(kind string) bool {
	return kind == "restart-unit" || kind == "restart-container" || kind == "kill-process" || kind == "apt-upgrade" || kind == "run-maintenance"
}

// MaintenanceUnits is the fixed run-maintenance mapping from Otto's task ids to
// reviewed oneshot units. Nothing else can be started through that kind.
var MaintenanceUnits = map[string]string{
	"backup-unlock":    "otto-maint-backup-unlock.service",
	"backup-cache-dir": "otto-maint-backup-cache-dir.service",
}

func ProtectedUnit(unit, aptUnit string) bool {
	return unit == "otto.service" || unit == "atlas.service" || unit == "tailscaled.service" || unit == aptUnit
}

// Load reads configuration from the environment and applies safe defaults.
//
// Required: ATLAS_TOKEN (unless ATLAS_DEV=1, which allows an empty token for local dev).
// Optional: ATLAS_ADDR (default 127.0.0.1:7788), ATLAS_AUDIT (default ./atlas-audit.log).
func Load() (Config, error) {
	cfg := Config{
		Addr:              envOr("ATLAS_ADDR", "127.0.0.1:7788"),
		Token:             strings.TrimSpace(os.Getenv("ATLAS_TOKEN")),
		AuditPath:         envOr("ATLAS_AUDIT", filepath.Join(".", "atlas-audit.log")),
		Actions:           list("ATLAS_ACTIONS"),
		RestartUnits:      list("ATLAS_RESTART_UNITS"),
		RestartContainers: list("ATLAS_RESTART_CONTAINERS"),
		KillUsers:         list("ATLAS_KILL_USERS"),
		AptUnit:           envOr("ATLAS_APT_UNIT", "atlas-apt-upgrade.service"),
		ActionDir:         envOr("ATLAS_ACTION_DIR", "atlas-actions"),
	}
	if cfg.Token == "" && os.Getenv("ATLAS_DEV") != "1" {
		return Config{}, errors.New("ATLAS_TOKEN is required (set ATLAS_DEV=1 to allow an empty token for local dev)")
	}
	if len(cfg.Actions) > 0 && cfg.Token == "" {
		return Config{}, errors.New("host actions require a non-empty ATLAS_TOKEN even in dev mode")
	}
	for _, kind := range cfg.Actions {
		if !KnownAction(kind) {
			return Config{}, fmt.Errorf("unknown ATLAS_ACTIONS kind %q", kind)
		}
	}
	if !UnitName.MatchString(cfg.AptUnit) || ProtectedUnit(cfg.AptUnit, "") {
		return Config{}, errors.New("invalid or protected ATLAS_APT_UNIT")
	}
	for _, unit := range cfg.RestartUnits {
		if !UnitName.MatchString(unit) || ProtectedUnit(unit, cfg.AptUnit) {
			return Config{}, fmt.Errorf("invalid or protected restart unit %q", unit)
		}
	}
	for _, name := range cfg.RestartContainers {
		if !ContainerName.MatchString(name) || name == "atlas" {
			return Config{}, fmt.Errorf("invalid or protected container %q", name)
		}
	}
	for _, user := range cfg.KillUsers {
		if user == "root" || user == "0" || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*\$?$`).MatchString(user) {
			return Config{}, fmt.Errorf("invalid or protected kill user %q", user)
		}
	}
	return cfg, nil
}

func list(key string) []string {
	var result []string
	for _, item := range strings.Split(os.Getenv(key), ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
