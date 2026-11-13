package config

import "testing"

func cleanEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"ATLAS_TOKEN", "ATLAS_DEV", "ATLAS_ACTIONS", "ATLAS_RESTART_UNITS", "ATLAS_RESTART_CONTAINERS", "ATLAS_KILL_USERS", "ATLAS_APT_UNIT", "ATLAS_ACTION_DIR", "ATLAS_AUDIT"} {
		t.Setenv(key, "")
	}
	t.Setenv("ATLAS_TOKEN", "secret")
}
func TestActionsDefaultOff(t *testing.T) {
	cleanEnv(t)
	cfg, err := Load()
	if err != nil || len(cfg.Actions) != 0 || cfg.ActionDir != "atlas-actions" || cfg.AptUnit != "atlas-apt-upgrade.service" {
		t.Fatalf("%+v %v", cfg, err)
	}
}
func TestActionConfigValidation(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"ATLAS_ACTIONS", "reboot"}, {"ATLAS_RESTART_UNITS", "otto.service"}, {"ATLAS_RESTART_UNITS", "atlas.service"}, {"ATLAS_RESTART_UNITS", "tailscaled.service"}, {"ATLAS_RESTART_UNITS", "atlas-apt-upgrade.service"},
		{"ATLAS_RESTART_UNITS", "--bad.service"}, {"ATLAS_RESTART_CONTAINERS", "atlas"}, {"ATLAS_RESTART_CONTAINERS", "foo;id"}, {"ATLAS_KILL_USERS", "root"}, {"ATLAS_KILL_USERS", "0"}, {"ATLAS_KILL_USERS", "1000"}, {"ATLAS_APT_UNIT", "otto.service"}, {"ATLAS_APT_UNIT", "foo.timer"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			cleanEnv(t)
			t.Setenv(tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("accepted unsafe config")
			}
		})
	}
	t.Run("empty dev token", func(t *testing.T) {
		cleanEnv(t)
		t.Setenv("ATLAS_TOKEN", "")
		t.Setenv("ATLAS_DEV", "1")
		t.Setenv("ATLAS_ACTIONS", "restart-unit")
		if _, err := Load(); err == nil {
			t.Fatal("enabled with empty token")
		}
	})
	t.Run("explicit lists", func(t *testing.T) {
		cleanEnv(t)
		t.Setenv("ATLAS_ACTIONS", "restart-unit, restart-container,kill-process,apt-upgrade,run-maintenance")
		t.Setenv("ATLAS_RESTART_UNITS", "demo.service")
		t.Setenv("ATLAS_RESTART_CONTAINERS", "my_app")
		t.Setenv("ATLAS_KILL_USERS", "demo")
		cfg, err := Load()
		if err != nil || len(cfg.Actions) != 5 || cfg.RestartUnits[0] != "demo.service" {
			t.Fatal(cfg, err)
		}
	})
}
