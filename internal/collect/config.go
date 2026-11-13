package collect

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strings"
)

// ConfigResult is one allowlisted config source, already redacted. Only
// readConfig constructs it, after RedactConfig has run over the content.
type ConfigResult struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	Content   string `json:"content"`
	Redacted  bool   `json:"redacted"`
	Truncated bool   `json:"truncated,omitempty"`
}

// ConfigError carries the HTTP status for a config read that returned nothing.
type ConfigError struct {
	Status int
	Reason string
}

func (e *ConfigError) Error() string { return e.Reason }

// BackupEnvPath is the only file the backup-env id maps to. The atlas user
// cannot read it directly; it needs this exact sudoers command.
const BackupEnvPath = "/etc/restic/env"

const (
	configMaxRead    = 256 << 10
	configMaxContent = 64 << 10
)

// ConfigSource is a validated config id; only ParseConfigID builds one.
type ConfigSource struct {
	id, unit string
}

// ParseConfigID accepts exactly backup-env or unit:<name.service|name.timer>.
// There is no path, glob or other id: this is not a generic file read.
func ParseConfigID(id string) (ConfigSource, error) {
	if id == "backup-env" {
		return ConfigSource{id: id}, nil
	}
	if unit, ok := strings.CutPrefix(id, "unit:"); ok && UnitPattern.MatchString(unit) {
		return ConfigSource{id: id, unit: unit}, nil
	}
	return ConfigSource{}, errors.New("unknown config id: expected unit:<name>.service, unit:<name>.timer or backup-env")
}

func Config(ctx context.Context, src ConfigSource) (ConfigResult, error) {
	return readConfig(ctx, src, boundedHeadCommand(configMaxRead+1))
}

func readConfig(ctx context.Context, src ConfigSource, run commandRunner) (ConfigResult, error) {
	var raw []byte
	var err error
	path := BackupEnvPath
	if src.unit != "" {
		raw, err = run(ctx, "systemctl", "cat", "--no-pager", "--", src.unit)
	} else {
		raw, err = run(ctx, "sudo", "-n", "/usr/bin/cat", BackupEnvPath)
	}
	if err != nil {
		var exitErr *exec.ExitError
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			return ConfigResult{}, &ConfigError{503, "config read timed out"}
		case src.unit != "" && errors.As(err, &exitErr):
			return ConfigResult{}, &ConfigError{404, "unit not found"}
		case src.unit != "":
			return ConfigResult{}, &ConfigError{503, warningFor(err, "systemctl", "unit files unavailable")}
		default:
			return ConfigResult{}, &ConfigError{503, warningFor(err, "sudo", "backup-env unavailable — grant the atlas user exactly: sudo -n /usr/bin/cat "+BackupEnvPath)}
		}
	}
	text := strings.ToValidUTF8(string(raw), "�")
	truncated := false
	if len(text) > configMaxRead {
		// Drop the cut final line: it could be the start of a secret whose
		// key name was cut off.
		text = text[:configMaxRead]
		if i := strings.LastIndexByte(text, '\n'); i >= 0 {
			text = text[:i+1]
		} else {
			text = ""
		}
		truncated = true
	}
	if src.unit != "" {
		path = unitFragmentPath(text)
	}
	content := RedactConfig(text, src.unit == "")
	if len(content) > configMaxContent {
		content = cutUTF8(content, configMaxContent)
		if i := strings.LastIndexByte(content, '\n'); i >= 0 {
			content = content[:i+1]
		}
		truncated = true
	}
	return ConfigResult{ID: src.id, Path: path, Content: content, Redacted: true, Truncated: truncated}, nil
}

// unitFragmentPath is the first "# /path" header systemctl cat prints.
func unitFragmentPath(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if p, ok := strings.CutPrefix(line, "# /"); ok && !strings.ContainsAny(p, " \t") {
			return "/" + p
		}
	}
	return ""
}

// backupEnvKeys are the only backup-env keys whose values are shown. Every
// other value, including unknown future keys, is redacted.
var backupEnvKeys = map[string]bool{
	"RESTIC_REPOSITORY": true, "RESTIC_CACHE_DIR": true, "RESTIC_COMPRESSION": true,
	"RESTIC_PACK_SIZE": true, "RESTIC_READ_CONCURRENCY": true, "RESTIC_HOST": true, "TMPDIR": true,
}

const redactedMark = "[REDACTED]"

const pemMark = "[REDACTED PEM BLOCK]"

var (
	secretKey = regexp.MustCompile(`(?i)pass|secret|token|key|cred|auth|account|session|cookie|private|signature|salt`)
	harmless  = regexp.MustCompile(`(?i)^(yes|no|true|false|on|off)?$`)
	// Leading punctuation (comment markers "#" and ";", option dashes, brackets)
	// is skipped, so a commented-out #Environment=TOKEN=x is still redacted.
	keyValue   = regexp.MustCompile(`^([^A-Za-z0-9_=\s]*([A-Za-z_][A-Za-z0-9_.-]*)=)(.*)$`)
	lineAssign = regexp.MustCompile(`^(\s*[^A-Za-z0-9_=\s]*\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*)(.*)$`)
	// URL query and fragment parameters: ?token=x, &api_key=x, #access_token=x.
	queryParam  = regexp.MustCompile(`([?&;#][A-Za-z0-9_.%\[\]-]*=)([^&#\s"']*)`)
	queryPart   = regexp.MustCompile(`[?#][^\s"']*`)
	colonSecret = regexp.MustCompile(`(?i)\b([\w-]*(?:pass|secret|token|key|cred|auth|cookie|private)[\w-]*)([ \t]*:[ \t]*)("[^"]*(?:"|$)|'[^']*(?:'|$)|\S+)`)
	flagSecret  = regexp.MustCompile(`(?i)(\s-{1,2}[\w-]*(?:pass|secret|token|key|cred|auth|account|cookie|private)[\w-]*)([ \t]+)("[^"]*(?:"|$)|'[^']*(?:'|$)|[^\s\\]+)`)
	authScheme  = regexp.MustCompile(`(?i)\b(bearer|basic|token)([ \t]+)[A-Za-z0-9._~+/=-]{8,}`)
	userinfo    = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@"']+@`)
	blob        = regexp.MustCompile(`^[A-Za-z0-9+/_-]{32,}={0,2}$`)
	digit       = regexp.MustCompile(`[0-9]`)
	letter      = regexp.MustCompile(`[A-Za-z]`)
	pemBegin    = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----`)
	pemEnd      = regexp.MustCompile(`-----END [A-Z0-9 ]+-----`)
	envLine     = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'#]*)\s*(?:#.*)?$`)
)

// RedactConfig removes secret-looking values from config text. Unit files get
// heuristic redaction: values of secret-named keys, flags and URL query
// parameters (also when commented out), URL userinfo,
// authorization headers, PEM blocks and long opaque blobs. strict (backup-env)
// is fail-closed: only backupEnvKeys keep a value, comments are withheld, and
// any line that is not one plain assignment is withheld entirely.
func RedactConfig(text string, strict bool) string {
	out := redactPass(text, strict)
	// The result must be a fixed point; if a second pass still finds something,
	// the heuristics disagree with themselves, so withhold everything.
	if redactPass(out, strict) != out {
		return "[REDACTED: content withheld]\n"
	}
	return out
}

func redactPass(text string, strict bool) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	inPEM := false
	for _, line := range lines {
		if inPEM {
			if pemEnd.MatchString(line) {
				inPEM = false
			}
			continue
		}
		if loc := pemBegin.FindStringIndex(line); loc != nil {
			out = append(out, line[:loc[0]]+pemMark)
			inPEM = !pemEnd.MatchString(line[loc[1]:])
			continue
		}
		if strict {
			out = append(out, redactEnvLine(line))
		} else {
			out = append(out, redactLine(line))
		}
	}
	return strings.Join(out, "\n")
}

func redactEnvLine(line string) string {
	trimmed := strings.TrimSpace(line)
	switch {
	case trimmed == "", trimmed == redactedMark, strings.HasSuffix(trimmed, pemMark):
		return line
	case strings.HasPrefix(trimmed, "#"):
		return "# " + redactedMark
	}
	m := envLine.FindStringSubmatch(line)
	if m == nil {
		return redactedMark
	}
	if !backupEnvKeys[m[1]] {
		return m[1] + "=" + redactedMark
	}
	// An allowlisted value is shown without any query string or fragment: a
	// repository URL needs neither, and either can carry a credential.
	return m[1] + "=" + queryPart.ReplaceAllString(redactLine(m[2]), "?"+redactedMark)
}

func redactLine(line string) string {
	// A secret-named key at the start of a line owns the rest of the line,
	// which also covers an unterminated quote.
	if m := lineAssign.FindStringSubmatch(line); m != nil && secretKey.MatchString(m[2]) && !harmless.MatchString(strings.TrimSpace(unquote(m[3]))) && m[3] != redactedMark {
		return m[1] + redactedMark
	}
	line = userinfo.ReplaceAllString(line, "${1}"+redactedMark+"@")
	line = queryParam.ReplaceAllStringFunc(line, func(p string) string {
		m := queryParam.FindStringSubmatch(p)
		if !secretKey.MatchString(m[1]) || harmless.MatchString(m[2]) || m[2] == redactedMark {
			return p
		}
		return m[1] + redactedMark
	})
	line = authScheme.ReplaceAllString(line, "${1}${2}"+redactedMark)
	line = flagSecret.ReplaceAllString(line, "${1}${2}"+redactedMark)
	line = colonSecret.ReplaceAllStringFunc(line, func(s string) string {
		m := colonSecret.FindStringSubmatch(s)
		if harmless.MatchString(unquote(m[3])) || m[3] == redactedMark || strings.HasPrefix(m[3], "//") {
			return s
		}
		return m[1] + m[2] + redactedMark
	})
	return redactWords(line, 0)
}

// redactWords splits a line into shell-like words, where a quoted run
// (including its spaces) belongs to the word around it, and redacts each.
func redactWords(s string, depth int) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '\t' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != '\t' {
			if q := s[j]; q == '"' || q == '\'' {
				if k := strings.IndexByte(s[j+1:], q); k >= 0 {
					j += k + 2
				} else {
					j = len(s)
				}
				continue
			}
			j++
		}
		b.WriteString(redactWord(s[i:j], depth))
		i = j
	}
	return b.String()
}

// redactWord handles KEY=VALUE, --flag=VALUE, and systemd's quoted
// Environment="A=1" "B_TOKEN=x y" words, recursing into non-secret values
// because they can themselves hold assignments (Environment=TOKEN=x).
func redactWord(w string, depth int) string {
	if depth > 4 || w == "" {
		return w
	}
	if q := w[0]; (q == '"' || q == '\'') && len(w) >= 2 && w[len(w)-1] == q && strings.IndexByte(w[1:len(w)-1], q) < 0 {
		inner := w[1 : len(w)-1]
		if m := keyValue.FindStringSubmatch(inner); m != nil {
			return w[:1] + m[1] + redactValue(m[2], m[3], depth) + w[:1]
		}
		return w[:1] + redactWords(inner, depth+1) + w[:1]
	}
	if m := keyValue.FindStringSubmatch(w); m != nil {
		return m[1] + redactValue(m[2], m[3], depth)
	}
	return w
}

func redactValue(key, value string, depth int) string {
	inner := unquote(value)
	if inner == redactedMark {
		return value
	}
	if (secretKey.MatchString(key) && !harmless.MatchString(inner)) || isBlob(inner) {
		return redactedMark
	}
	return redactWord(value, depth+1)
}

func unquote(v string) string {
	if len(v) > 0 && (v[0] == '"' || v[0] == '\'') {
		v = v[1:]
		if len(v) > 0 && (v[len(v)-1] == '"' || v[len(v)-1] == '\'') {
			v = v[:len(v)-1]
		}
	}
	return v
}

func isBlob(v string) bool {
	return !strings.HasPrefix(v, "/") && blob.MatchString(v) && digit.MatchString(v) && letter.MatchString(v)
}

// boundedHeadCommand keeps only the first limit bytes of stdout.
func boundedHeadCommand(limit int) commandRunner {
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out := &headBuffer{limit: limit}
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdout = out
		err := cmd.Run()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return out.data, err
	}
}

type headBuffer struct {
	limit int
	data  []byte
}

func (h *headBuffer) Write(p []byte) (int, error) {
	if room := h.limit - len(h.data); room > 0 {
		h.data = append(h.data, p[:min(room, len(p))]...)
	}
	return len(p), nil
}
