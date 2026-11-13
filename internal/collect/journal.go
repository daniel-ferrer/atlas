package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type JournalLine struct {
	Ts       int64  `json:"ts"`
	Unit     string `json:"unit"`
	Priority int    `json:"priority"`
	Message  string `json:"message"`
}
type JournalResult struct {
	Lines []JournalLine `json:"lines"`
	// Truncated reports that older lines were dropped or a message was cut to
	// stay inside the byte bounds below.
	Truncated bool   `json:"truncated,omitempty"`
	Warning   string `json:"warning,omitempty"`
}
type JournalQuery struct {
	Unit, Priority string
	Lines          int
}

// Bounds for the journal endpoint. A unit-scoped read is an evidence slice for
// Otto, so it is tighter than the global tail the dashboard shows.
const (
	journalDefaultLines = 200
	journalMaxLines     = 1000
	journalMaxUnitLines = 300
	journalMaxMessage   = 4 << 10
	journalMaxUnitBytes = 64 << 10
	journalMaxBytes     = 1 << 20
	journalMaxRead      = 8 << 20
)

// UnitPattern accepts one exact service or timer name. The leading
// alphanumeric rules out option-like names even though argv already uses --unit=.
var UnitPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:\\-]{0,240}\.(service|timer)$`)
var unitChars = regexp.MustCompile(`^[A-Za-z0-9@._:\\-]+$`)
var priorityPattern = regexp.MustCompile(`^[0-7](\.\.[0-7])?$`)

func NewJournalQuery(unit, priority, lines string) (JournalQuery, error) {
	q := JournalQuery{Unit: unit, Priority: priority, Lines: journalDefaultLines}
	limit := journalMaxLines
	if unit != "" {
		limit = journalMaxUnitLines
	}
	if lines != "" {
		if n, err := strconv.Atoi(lines); err == nil {
			q.Lines = max(1, min(limit, n))
		}
	}
	if unit != "" {
		if !unitChars.MatchString(unit) {
			return q, fmt.Errorf("invalid unit")
		}
		if !strings.Contains(unit, ".") {
			q.Unit += ".service"
		}
		if !UnitPattern.MatchString(q.Unit) {
			return q, fmt.Errorf("invalid unit: expected one .service or .timer name")
		}
	}
	if priority != "" && !priorityPattern.MatchString(priority) {
		return q, fmt.Errorf("invalid priority")
	}
	return q, nil
}

func Journal(ctx context.Context, q JournalQuery) JournalResult {
	return collectJournal(ctx, q, boundedCommand(journalMaxRead))
}
func collectJournal(ctx context.Context, q JournalQuery, run commandRunner) JournalResult {
	raw, err := run(ctx, "journalctl", journalArgs(q)...)
	if err != nil {
		return JournalResult{Lines: []JournalLine{}, Warning: warningFor(err, "journalctl", "journal unavailable — add the atlas user to the systemd-journal group")}
	}
	total := journalMaxBytes
	if q.Unit != "" {
		total = journalMaxUnitBytes
	}
	lines, truncated := boundJournal(parseJournal(raw), journalMaxMessage, total)
	return JournalResult{Lines: lines, Truncated: truncated}
}
func journalArgs(q JournalQuery) []string {
	a := []string{"--output=json", "-n", strconv.Itoa(q.Lines), "--no-pager"}
	if q.Unit != "" {
		a = append(a, "--unit="+q.Unit)
	}
	if q.Priority != "" {
		a = append(a, "--priority="+q.Priority)
	}
	return a
}

// boundJournal cuts each message to perMessage bytes, then drops the oldest
// lines until the messages fit in total bytes.
func boundJournal(lines []JournalLine, perMessage, total int) ([]JournalLine, bool) {
	truncated := false
	for i := range lines {
		if len(lines[i].Message) > perMessage {
			lines[i].Message = cutUTF8(lines[i].Message, perMessage) + "…"
			truncated = true
		}
	}
	size, start := 0, len(lines)
	for start > 0 && size+len(lines[start-1].Message) <= total {
		size += len(lines[start-1].Message)
		start--
	}
	if start > 0 {
		truncated = true
	}
	return lines[start:], truncated
}

// cutUTF8 keeps at most n bytes without splitting a code point.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func parseJournal(raw []byte) []JournalLine {
	out := []JournalLine{}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var row map[string]json.RawMessage
		if json.Unmarshal(line, &row) != nil {
			continue
		}
		var tsText, pText, unit, message string
		_ = json.Unmarshal(row["__REALTIME_TIMESTAMP"], &tsText)
		_ = json.Unmarshal(row["PRIORITY"], &pText)
		for _, key := range []string{"_SYSTEMD_UNIT", "_SYSTEMD_USER_UNIT", "SYSLOG_IDENTIFIER"} {
			if json.Unmarshal(row[key], &unit) == nil && unit != "" {
				break
			}
		}
		if json.Unmarshal(row["MESSAGE"], &message) != nil {
			var b []byte
			if json.Unmarshal(row["MESSAGE"], &b) == nil {
				message = strings.ToValidUTF8(string(b), "�")
			}
		}
		micros, _ := strconv.ParseInt(tsText, 10, 64)
		priority, err := strconv.Atoi(pText)
		if err != nil || priority < 0 || priority > 7 {
			priority = 6
		}
		out = append(out, JournalLine{Ts: micros / 1000, Unit: unit, Priority: priority, Message: message})
	}
	return out
}
