package collect

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// Every planted secret contains "s3cr3t" so one substring check proves none leaked.
const unitFixture = `# /etc/systemd/system/home-backup.service
[Unit]
Description=Home backup
After=network-online.target

[Service]
Type=oneshot
PrivateTmp=yes
EnvironmentFile=/etc/restic/env
ExecStart=/usr/local/bin/home-backup --repo rest:https://bob:s3cr3t-a@backup.example/ --password s3cr3t-b
ExecStartPost=/usr/bin/curl -H "Authorization: Bearer s3cr3t-c-0123456789" https://hc.example/ping
Environment="A=1" "API_TOKEN=s3cr3t-d with spaces" B=2
Environment=WEBHOOK_KEY=s3cr3t-e PLAIN=visible

# /etc/systemd/system/home-backup.service.d/override.conf
[Service]
Environment=DB_PASSWORD="s3cr3t-f quoted"
Environment='SESSION_COOKIE=s3cr3t-g'
ExecStart=/usr/bin/tool --api-key=s3cr3t-h --token='s3cr3t-i'
Environment=OPAQUE=s3cr3tAbcdefghijklmnopqrstuvwxyz0123
X-Api-Key: s3cr3t-j
-----BEGIN OPENSSH PRIVATE KEY-----
s3cr3t-k
-----END OPENSSH PRIVATE KEY-----
User=backup
`

const envFixture = `# repo for B2, password is s3cr3t-0
export RESTIC_REPOSITORY="rest:https://user:s3cr3t-1@backup.example/repo"
RESTIC_PASSWORD=s3cr3t-2
RESTIC_PASSWORD_FILE=/root/s3cr3t-3
AWS_ACCESS_KEY_ID=s3cr3t-4
AWS_SECRET_ACCESS_KEY=s3cr3t-5
B2_ACCOUNT_ID=s3cr3t-6
SOME_FUTURE_THING=s3cr3t-7
RESTIC_CACHE_DIR=/var/cache/restic
s3cr3t-8 bare line
RESTIC_COMPRESSION=auto # trailing note s3cr3t-9
-----BEGIN PGP PRIVATE KEY BLOCK-----
s3cr3t-10
`

func TestRedactUnitFile(t *testing.T) {
	got := RedactConfig(unitFixture, false)
	if strings.Contains(got, "s3cr3t") {
		t.Fatalf("secret leaked:\n%s", got)
	}
	for _, keep := range []string{
		"# /etc/systemd/system/home-backup.service.d/override.conf", "Type=oneshot", "PrivateTmp=yes",
		"EnvironmentFile=/etc/restic/env", "B=2", "PLAIN=visible", `"A=1"`, "User=backup",
		"https://[REDACTED]@backup.example/", `"Authorization: [REDACTED]`, "[REDACTED PEM BLOCK]", "After=network-online.target",
		`"API_TOKEN=[REDACTED]"`, "WEBHOOK_KEY=[REDACTED]", "X-Api-Key: [REDACTED]",
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("missing %q in:\n%s", keep, got)
		}
	}
	if RedactConfig(got, false) != got {
		t.Fatal("redaction is not idempotent")
	}
}

func TestRedactBackupEnvIsFailClosed(t *testing.T) {
	got := RedactConfig(envFixture, true)
	if strings.Contains(got, "s3cr3t") {
		t.Fatalf("secret leaked:\n%s", got)
	}
	for _, keep := range []string{
		`RESTIC_REPOSITORY="rest:https://[REDACTED]@backup.example/repo"`, "RESTIC_PASSWORD=[REDACTED]",
		"RESTIC_PASSWORD_FILE=[REDACTED]", "SOME_FUTURE_THING=[REDACTED]", "RESTIC_CACHE_DIR=/var/cache/restic",
		"RESTIC_COMPRESSION=auto", "[REDACTED PEM BLOCK]",
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("missing %q in:\n%s", keep, got)
		}
	}
}

func TestRedactEdgeShapes(t *testing.T) {
	for _, in := range []string{
		`TOKEN="unterminated s3cr3t`, `Environment=TOKEN="s3cr3t two"`, `PASS = s3cr3t`, `password: "s3cr3t x"`,
		`ExecStart=/x --secret "s3cr3t y"`, `ExecStart=/x "--token=s3cr3t"`, `URL=postgres://u:s3cr3t@db/x`,
		`Environment="X=1" "PRIVATE_KEY=s3cr3t"`, `Authorization: Basic czNjcjN0OnMzY3IzdA==s3cr3t`,
		`ExecStart=/x -e GITHUB_TOKEN=s3cr3t`, `-----BEGIN RSA PRIVATE KEY----- s3cr3t`,
		// Commented out with no space after the comment marker.
		`#Environment=RESTIC_PASSWORD=s3cr3t`, `#RESTIC_PASSWORD=s3cr3t`, `;Environment=API_TOKEN=s3cr3t`,
		`#Environment="API_TOKEN=s3cr3t two"`, `#"API_TOKEN=s3cr3t two"`, `;;  DB_PASS = s3cr3t`, `#ExecStart=/x --password=s3cr3t`,
		`(TOKEN=s3cr3t)`, `#X-Api-Key: s3cr3t`,
		// Secret-named URL query and fragment parameters.
		`ExecStartPost=/usr/bin/curl -fsS https://api.example.com/push?token=s3cr3t`,
		`ExecStartPost=/usr/bin/curl "https://x/ping?api_key=s3cr3t&a=1"`, `ExecStart=/x https://x/p?a=1&access_token=s3cr3t#f`,
		`ExecStart=/x 'https://x/p?sig=1&Signature=s3cr3t'`, `ExecStart=/x https://x/cb#access_token=s3cr3t`,
		`#ExecStartPost=/usr/bin/curl https://x/?auth=s3cr3t`,
	} {
		if got := RedactConfig(in, false); strings.Contains(got, "s3cr3t") {
			t.Errorf("%q -> %q", in, got)
		}
	}
}

func TestRedactKeepsNonSecretQueryAndComments(t *testing.T) {
	in := "#Environment=LOG_LEVEL=debug\nExecStart=/usr/bin/curl https://x/ping?a=1&b=two\n# Comment: not secret"
	if got := RedactConfig(in, false); got != in {
		t.Fatalf("over-redacted: %q", got)
	}
	if got := RedactConfig("ExecStart=/x https://x/p?a=1&token=abc&b=2", false); got != "ExecStart=/x https://x/p?a=1&token=[REDACTED]&b=2" {
		t.Fatal(got)
	}
}

func TestRedactBackupEnvRepositoryQuery(t *testing.T) {
	for _, in := range []string{
		"RESTIC_REPOSITORY=b2:bucket:/p?token=s3cr3t", `RESTIC_REPOSITORY="rest:https://h/r?x=s3cr3t"`,
		"RESTIC_REPOSITORY=s3:https://h/b#s3cr3t", "RESTIC_REPOSITORY=rest:https://h/r?s3cr3t",
	} {
		got := RedactConfig(in, true)
		// An unquoted "#..." is dropped as a trailing comment instead of marked.
		marked := strings.Contains(got, "?[REDACTED]") || !strings.Contains(in, "?") && !strings.Contains(in, `"`)
		if strings.Contains(got, "s3cr3t") || !strings.HasPrefix(got, "RESTIC_REPOSITORY=") || !marked {
			t.Errorf("%q -> %q", in, got)
		}
	}
	if got := RedactConfig("RESTIC_REPOSITORY=s3:s3.amazonaws.com/bucket/repo", true); got != "RESTIC_REPOSITORY=s3:s3.amazonaws.com/bucket/repo" {
		t.Fatal(got)
	}
}

func TestParseConfigID(t *testing.T) {
	for _, ok := range []string{"backup-env", "unit:home-backup.service", "unit:backup@night.service", "unit:home-backup.timer"} {
		if src, err := ParseConfigID(ok); err != nil || src.id != ok {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "unit:", "unit:home-backup", "unit:../x.service", "unit:a.service;x", "unit:-x.service", "unit:--all.service",
		"/etc/restic/env", "backup-env ", "file:/etc/passwd", "unit:a.mount", "UNIT:a.service", "unit:a.service\n"} {
		if _, err := ParseConfigID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestReadConfigArgvAndShape(t *testing.T) {
	var argv []string
	run := func(out string, err error) commandRunner {
		return func(_ context.Context, name string, args ...string) ([]byte, error) {
			argv = append([]string{name}, args...)
			return []byte(out), err
		}
	}
	src, _ := ParseConfigID("unit:home-backup.service")
	r, err := readConfig(context.Background(), src, run(unitFixture, nil))
	if err != nil || !r.Redacted || r.ID != "unit:home-backup.service" || r.Path != "/etc/systemd/system/home-backup.service" || strings.Contains(r.Content, "s3cr3t") {
		t.Fatalf("%v %#v", err, r)
	}
	if !reflect.DeepEqual(argv, []string{"systemctl", "cat", "--no-pager", "--", "home-backup.service"}) {
		t.Fatal(argv)
	}
	if _, err = readConfig(context.Background(), src, run("", &exec.ExitError{})); !isStatus(err, 404) {
		t.Fatal(err)
	}
	if _, err = readConfig(context.Background(), src, run("", exec.ErrNotFound)); !isStatus(err, 503) {
		t.Fatal(err)
	}

	env, _ := ParseConfigID("backup-env")
	r, err = readConfig(context.Background(), env, run(envFixture, nil))
	if err != nil || !r.Redacted || r.Path != BackupEnvPath || strings.Contains(r.Content, "s3cr3t") {
		t.Fatalf("%v %#v", err, r)
	}
	if !reflect.DeepEqual(argv, []string{"sudo", "-n", "/usr/bin/cat", "/etc/restic/env"}) {
		t.Fatal(argv)
	}
	if _, err = readConfig(context.Background(), env, run("", &exec.ExitError{})); !isStatus(err, 503) || !strings.Contains(err.Error(), "sudoers") && !strings.Contains(err.Error(), "sudo -n") {
		t.Fatal(err)
	}
	if _, err = readConfig(context.Background(), env, run("", context.DeadlineExceeded)); !isStatus(err, 503) {
		t.Fatal(err)
	}
}

func TestReadConfigBounds(t *testing.T) {
	big := strings.Repeat("PLAIN=visible-value-0123\n", configMaxRead/10) + "API_TOKEN=s3cr3t-cut"
	src, _ := ParseConfigID("unit:a.service")
	r, err := readConfig(context.Background(), src, func(context.Context, string, ...string) ([]byte, error) { return []byte(big), nil })
	if err != nil || !r.Truncated || len(r.Content) > configMaxContent || strings.Contains(r.Content, "s3cr3t") || !strings.HasSuffix(r.Content, "\n") {
		t.Fatalf("%v truncated=%v len=%d", err, r.Truncated, len(r.Content))
	}
	h := &headBuffer{limit: 4}
	_, _ = h.Write([]byte("abc"))
	_, _ = h.Write([]byte("defg"))
	if string(h.data) != "abcd" {
		t.Fatal(string(h.data))
	}
}

func isStatus(err error, status int) bool {
	var ce *ConfigError
	return errors.As(err, &ce) && ce.Status == status
}
