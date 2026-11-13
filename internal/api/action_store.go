package api

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// No reservation is removed, even when its request was refused. O_EXCL also
// protects against simultaneous requests handled by separate agent processes.
func reserve(dir, name string, value any) error {
	// The parent must already exist, so syncing it durably records a newly
	// created store (including on its very first request).
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return syncDir(dir)
}

// active.json is intentionally retained after ambiguous outcomes or crashes.
// Only an operator who has reconciled the host may clear that interlock.
func clearActive(dir string) error {
	if err := os.Remove(filepath.Join(dir, "active.json")); err != nil {
		return err
	}
	return syncDir(dir)
}
