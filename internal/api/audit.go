package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type auditSink interface{ write(map[string]any) error }

// The execution gate requires both the entry and its directory to be durable.
// An audit failure before dispatch always prevents the host operation.
type auditor struct {
	mu   sync.Mutex
	path string
}

func newAuditor(path string) *auditor { return &auditor{path: path} }
func (a *auditor) write(entry map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return syncDir(filepath.Dir(a.path))
}
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
