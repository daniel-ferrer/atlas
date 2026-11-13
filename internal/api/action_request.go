package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/daniel-ferrer/atlas/internal/config"
	"github.com/daniel-ferrer/atlas/internal/hostops"
)

type actionRequest struct {
	ID                               string                     `json:"id"`
	Kind                             string                     `json:"kind"`
	Target                           map[string]json.RawMessage `json:"target"`
	Command                          string                     `json:"command"`
	unit, name, user, processCommand string
	pid                              int32
	startedAt                        int64
}

var actionID = regexp.MustCompile(`^ha_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var quoteSafe = regexp.MustCompile(`^[A-Za-z0-9@._:/=+-]+$`)

// Exact objects reject duplicate keys, case variants, null, and unknown fields.
// encoding/json's struct decoder alone accepts duplicate and case-folded keys.
func object(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("invalid object key")
		}
		if _, exists := m[key]; exists {
			return nil, errors.New("duplicate object key")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, err
		}
		m[key] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return m, nil
}
func exactKeys(m map[string]json.RawMessage, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return false
		}
	}
	return true
}
func textField(m map[string]json.RawMessage, key string) (string, error) {
	var s string
	if err := json.Unmarshal(m[key], &s); err != nil || s == "" {
		return "", fmt.Errorf("%s must be a non-empty string", key)
	}
	return s, nil
}
func integerField(m map[string]json.RawMessage, key string) (int64, error) {
	raw := string(m[key])
	if raw == "" || strings.ContainsAny(raw, ".eE\"+") {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return strconv.ParseInt(raw, 10, 64)
}
func parseAction(raw []byte) (a actionRequest, err error) {
	if !utf8.Valid(raw) {
		return a, errors.New("invalid UTF-8")
	}
	m, err := object(raw)
	if err != nil {
		return a, err
	}
	if !exactKeys(m, "id", "kind", "target", "command") {
		return a, errors.New("expected exactly id, kind, target and command")
	}
	if a.ID, err = textField(m, "id"); err != nil || !actionID.MatchString(a.ID) {
		return a, errors.New("invalid action id")
	}
	if a.Kind, err = textField(m, "kind"); err != nil || !config.KnownAction(a.Kind) {
		return a, errors.New("unknown action kind")
	}
	if a.Command, err = textField(m, "command"); err != nil {
		return a, err
	}
	a.Target, err = object(m["target"])
	if err != nil {
		return a, err
	}
	switch a.Kind {
	case "restart-unit":
		if !exactKeys(a.Target, "unit") {
			return a, errors.New("expected unit target")
		}
		a.unit, err = textField(a.Target, "unit")
		if err != nil || !config.UnitName.MatchString(a.unit) {
			return a, errors.New("invalid unit")
		}
	case "restart-container":
		if !exactKeys(a.Target, "name") {
			return a, errors.New("expected name target")
		}
		a.name, err = textField(a.Target, "name")
		if err != nil || !config.ContainerName.MatchString(a.name) {
			return a, errors.New("invalid container name")
		}
	case "kill-process":
		if !exactKeys(a.Target, "pid", "user", "command", "startedAt") {
			return a, errors.New("expected complete process identity")
		}
		pid, e := integerField(a.Target, "pid")
		if e != nil || pid < 3 || pid > 2147483647 {
			return a, errors.New("invalid pid")
		}
		a.pid = int32(pid)
		if a.user, err = textField(a.Target, "user"); err != nil {
			return a, err
		}
		if a.processCommand, err = textField(a.Target, "command"); err != nil {
			return a, err
		}
		a.startedAt, err = integerField(a.Target, "startedAt")
		if err != nil || a.startedAt <= 0 || a.startedAt > 9007199254740991 {
			return a, errors.New("invalid startedAt")
		}
	case "apt-upgrade":
		if !exactKeys(a.Target) {
			return a, errors.New("apt target must be empty")
		}
	case "run-maintenance":
		if !exactKeys(a.Target, "task") {
			return a, errors.New("expected task target")
		}
		task, e := textField(a.Target, "task")
		if a.unit = config.MaintenanceUnits[task]; e != nil || a.unit == "" {
			return a, errors.New("unknown maintenance task")
		}
	}
	return a, nil
}
func shellQuote(s string) string {
	if quoteSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
func (a actionRequest) canonical() string {
	var commands [][]string
	switch a.Kind {
	case "restart-unit":
		commands = [][]string{{"systemctl", "restart", a.unit}}
	case "restart-container":
		commands = [][]string{{"docker", "restart", a.name}}
	case "kill-process":
		commands = [][]string{{"kill", "-TERM", strconv.Itoa(int(a.pid))}}
	case "apt-upgrade":
		commands = hostops.AptCommands
	case "run-maintenance":
		commands = [][]string{{"systemctl", "start", a.unit}}
	}
	lines := make([]string, len(commands))
	for i, args := range commands {
		quoted := make([]string, len(args))
		for j, arg := range args {
			quoted[j] = shellQuote(arg)
		}
		lines[i] = strings.Join(quoted, " ")
	}
	return strings.Join(lines, " && ")
}
