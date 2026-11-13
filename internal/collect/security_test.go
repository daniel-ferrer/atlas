package collect

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestSecurityParsers(t *testing.T) {
	apt := parseAptSimulate([]byte("Inst openssl [1.0] (1.1 Debian-Security:stable-security [amd64])\nInst curl [7] (8 Debian:stable [amd64])\nInst fresh (2 Debian:stable [amd64])\n"))
	if len(apt) != 3 || !apt[0].Security || apt[1].Security || apt[2].From != "" {
		t.Fatalf("apt: %+v", apt)
	}
	b := parseFail2banStatus([]byte("`- Banned IP list:\t1.2.3.4 5.6.7.8\n"))
	if len(b) != 2 {
		t.Fatalf("bans: %+v", b)
	}
	jails := parseFail2banJails([]byte("`- Jail list:\tsshd, recidive\n"))
	if !reflect.DeepEqual(jails, []string{"sshd", "recidive"}) {
		t.Fatalf("jails: %+v", jails)
	}
	now := time.Date(2025, 1, 2, 12, 30, 0, 0, time.UTC)
	h := sshFailureHistogram([]JournalLine{{Ts: now.Add(-23 * time.Hour).UnixMilli(), Message: "Failed password"}, {Ts: now.Add(-time.Minute).UnixMilli(), Message: "Invalid user"}}, now)
	if h.Last24h != 2 || h.Hourly[0] != 1 || h.Hourly[23] != 1 {
		t.Fatalf("histogram: %+v", h)
	}
	s := parseSudoEvents([]JournalLine{{Ts: 4, Message: "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id"}})
	if len(s) != 1 || s[0].User != "alice" || s[0].Command != "/bin/id" {
		t.Fatalf("sudo: %+v", s)
	}
}

func TestSecurityFail2banUsesSudoAndEnumeratesJails(t *testing.T) {
	type invocation struct {
		name string
		args []string
	}
	var fail2banCalls []invocation
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "sudo" {
			return []byte{}, nil
		}
		fail2banCalls = append(fail2banCalls, invocation{name: name, args: append([]string(nil), args...)})
		switch {
		case reflect.DeepEqual(args, []string{"-n", "fail2ban-client", "status"}):
			return []byte("`- Jail list:\tsshd, recidive\n"), nil
		case reflect.DeepEqual(args, []string{"-n", "fail2ban-client", "status", "sshd"}):
			return []byte("`- Banned IP list:\t1.2.3.4\n"), nil
		case reflect.DeepEqual(args, []string{"-n", "fail2ban-client", "status", "recidive"}):
			return []byte("`- Banned IP list:\t5.6.7.8\n"), nil
		default:
			return nil, errors.New("unexpected sudo command")
		}
	}

	r := collectSecurity(context.Background(), run, time.Now())
	if got := []string{r.Bans[0].IP, r.Bans[1].IP}; !reflect.DeepEqual(got, []string{"1.2.3.4", "5.6.7.8"}) {
		t.Fatalf("bans: %+v", r.Bans)
	}
	want := []invocation{
		{name: "sudo", args: []string{"-n", "fail2ban-client", "status"}},
		{name: "sudo", args: []string{"-n", "fail2ban-client", "status", "sshd"}},
		{name: "sudo", args: []string{"-n", "fail2ban-client", "status", "recidive"}},
	}
	if !reflect.DeepEqual(fail2banCalls, want) {
		t.Fatalf("calls: %#v", fail2banCalls)
	}
}

func TestSecurityFail2banPartialFailureKeepsBans(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "sudo" {
			return []byte{}, nil
		}
		if len(args) == 3 {
			return []byte("`- Jail list:\tsshd, recidive\n"), nil
		}
		if args[len(args)-1] == "sshd" {
			return []byte("`- Banned IP list:\t1.2.3.4\n"), nil
		}
		return nil, errors.New("sudo denied")
	}
	r := collectSecurity(context.Background(), run, time.Now())
	if len(r.Bans) != 1 || r.Bans[0].IP != "1.2.3.4" || r.Warning == "" {
		t.Fatalf("result: %+v", r)
	}
}

func TestSecurityIndependentDegrade(t *testing.T) {
	r := collectSecurity(context.Background(), func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("permission denied") }, time.Now())
	if r.Warning == "" || r.Bans == nil || r.PendingUpdates == nil || len(r.SSHFailures.Hourly) != 24 {
		t.Fatalf("result: %+v", r)
	}
}
