package collect

import (
	"context"
	"regexp"
	"strings"
	"time"
)

type SSHFailures struct {
	Last24h int     `json:"last24h"`
	Hourly  [24]int `json:"hourly"`
}
type Ban struct {
	IP    string `json:"ip"`
	Tries int    `json:"tries"`
	Until *int64 `json:"until"`
}
type PendingUpdate struct {
	Package  string `json:"package"`
	From     string `json:"from"`
	To       string `json:"to"`
	Security bool   `json:"security"`
}
type SudoEvent struct {
	Ts      int64  `json:"ts"`
	User    string `json:"user"`
	Command string `json:"command"`
}
type SecurityResult struct {
	SSHFailures    SSHFailures     `json:"sshFailures"`
	Bans           []Ban           `json:"bans"`
	PendingUpdates []PendingUpdate `json:"pendingUpdates"`
	SudoEvents     []SudoEvent     `json:"sudoEvents"`
	Warning        string          `json:"warning,omitempty"`
}

func Security(ctx context.Context) SecurityResult {
	return collectSecurity(ctx, execCommand, time.Now())
}
func collectSecurity(ctx context.Context, run commandRunner, now time.Time) SecurityResult {
	r := SecurityResult{Bans: []Ban{}, PendingUpdates: []PendingUpdate{}, SudoEvents: []SudoEvent{}}
	var w []string
	args := []string{"--since=-24h", "--output=json", "--no-pager", "-n", "5000"}
	if raw, e := run(ctx, "journalctl", append(args, "SYSLOG_IDENTIFIER=sshd")...); e != nil {
		w = append(w, warningFor(e, "sshd journal", "SSH failures unavailable — add the atlas user to the systemd-journal group"))
	} else {
		r.SSHFailures = sshFailureHistogram(parseJournal(raw), now)
	}
	if raw, e := run(ctx, "journalctl", append(args, "SYSLOG_IDENTIFIER=sudo")...); e != nil {
		w = append(w, warningFor(e, "sudo journal", "sudo events unavailable — add the atlas user to the systemd-journal group"))
	} else {
		r.SudoEvents = parseSudoEvents(parseJournal(raw))
	}
	if raw, e := run(ctx, "sudo", "-n", "fail2ban-client", "status"); e != nil {
		w = append(w, warningFor(e, "fail2ban-client", "fail2ban bans unavailable — grant a narrowly scoped sudoers entry for fail2ban-client status sshd"))
	} else {
		for _, jail := range parseFail2banJails(raw) {
			jailRaw, jailErr := run(ctx, "sudo", "-n", "fail2ban-client", "status", jail)
			if jailErr != nil {
				w = append(w, warningFor(jailErr, "fail2ban-client", "fail2ban bans unavailable — grant a narrowly scoped sudoers entry for fail2ban-client status sshd"))
				continue
			}
			r.Bans = append(r.Bans, parseFail2banStatus(jailRaw)...)
		}
	}
	if raw, e := run(ctx, "apt-get", "-s", "dist-upgrade"); e != nil {
		w = append(w, warningFor(e, "apt-get", "pending updates unavailable — install apt and permit package metadata reads"))
	} else {
		r.PendingUpdates = parseAptSimulate(raw)
	}
	r.Warning = joinWarnings(w...)
	return r
}
func sshFailureHistogram(lines []JournalLine, now time.Time) SSHFailures {
	var r SSHFailures
	start := now.Truncate(time.Hour).Add(-23 * time.Hour)
	for _, l := range lines {
		if !strings.Contains(l.Message, "Failed password") && !strings.Contains(l.Message, "Invalid user") {
			continue
		}
		t := time.UnixMilli(l.Ts)
		if t.Before(now.Add(-24*time.Hour)) || t.After(now) {
			continue
		}
		i := int(t.Sub(start) / time.Hour)
		if i >= 0 && i < 24 {
			r.Hourly[i]++
			r.Last24h++
		}
	}
	return r
}

var sudoRE = regexp.MustCompile(`^([^ :]+)\s*:.*;\s*COMMAND=(.*)$`)

func parseSudoEvents(lines []JournalLine) []SudoEvent {
	out := []SudoEvent{}
	for _, l := range lines {
		m := sudoRE.FindStringSubmatch(l.Message)
		if len(m) > 0 {
			out = append(out, SudoEvent{Ts: l.Ts, User: m[1], Command: strings.TrimSpace(m[2])})
		}
	}
	if len(out) > 100 {
		return out[len(out)-100:]
	}
	return out
}
func parseFail2banStatus(raw []byte) []Ban {
	out := []Ban{}
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.Index(line, "Banned IP list:"); i >= 0 {
			for _, ip := range strings.Fields(line[i+len("Banned IP list:"):]) {
				out = append(out, Ban{IP: ip})
			}
		}
	}
	return out
}
func parseFail2banJails(raw []byte) []string {
	out := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.Index(line, "Jail list:"); i >= 0 {
			for _, jail := range strings.Split(line[i+len("Jail list:"):], ",") {
				if jail = strings.TrimSpace(jail); jail != "" {
					out = append(out, jail)
				}
			}
		}
	}
	return out
}

var aptRE = regexp.MustCompile(`^Inst\s+(\S+)(?:\s+\[([^]]+)\])?\s+\((\S+)\s+([^)]*)\)`)

func parseAptSimulate(raw []byte) []PendingUpdate {
	out := []PendingUpdate{}
	for _, line := range strings.Split(string(raw), "\n") {
		m := aptRE.FindStringSubmatch(line)
		if len(m) > 0 {
			origin := strings.ToLower(m[4])
			out = append(out, PendingUpdate{Package: m[1], From: m[2], To: m[3], Security: strings.Contains(origin, "-security") || strings.Contains(origin, "debian-security")})
		}
	}
	return out
}
