package collect

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseJournal(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want JournalLine
	}{
		{"string message", "{\"__REALTIME_TIMESTAMP\":\"1700000000123456\",\"PRIORITY\":\"3\",\"_SYSTEMD_UNIT\":\"ssh.service\",\"MESSAGE\":\"hello\"}\n", JournalLine{Ts: 1700000000123, Unit: "ssh.service", Priority: 3, Message: "hello"}},
		{"byte message and fallback", "not json\n{\"__REALTIME_TIMESTAMP\":\"2000\",\"_SYSTEMD_USER_UNIT\":\"app.service\",\"MESSAGE\":[72,105]}\n", JournalLine{Ts: 2, Unit: "app.service", Priority: 6, Message: "Hi"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseJournal([]byte(tt.raw))
			if len(got) != 1 || !reflect.DeepEqual(got[0], tt.want) {
				t.Fatalf("unexpected: %#v", got)
			}
		})
	}
}

func TestJournalQuery(t *testing.T) {
	tests := []struct {
		name, unit, priority, lines string
		ok                          bool
		wantLines                   int
	}{
		{"defaults", "", "", "", true, 200}, {"clamp high", "", "3..5", "9999", true, 1000},
		{"unit clamp high", "ssh", "3..5", "9999", true, 300}, {"unit clamp low", "ssh.service", "", "0", true, 1},
		{"timer", "home-backup.timer", "", "50", true, 50}, {"template instance", "backup@night.service", "", "", true, 200},
		{"bad unit", "ssh;rm", "", "20", false, 20}, {"bad priority", "", "verbose", "20", false, 20}, {"nonnumeric", "", "", "x", true, 200},
		{"other unit type", "home.mount", "", "", false, 200}, {"double suffix", "foo.bar", "", "", false, 200},
		{"option-like", "--all", "", "", false, 200}, {"option-like suffixed", "-x.service", "", "", false, 200},
		{"too long", strings.Repeat("a", 250) + ".service", "", "", false, 200}, {"traversal", "../x.service", "", "", false, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := NewJournalQuery(tt.unit, tt.priority, tt.lines)
			if (err == nil) != tt.ok {
				t.Fatalf("err=%v", err)
			}
			if q.Lines != tt.wantLines {
				t.Fatalf("lines=%d", q.Lines)
			}
		})
	}
	q, _ := NewJournalQuery("ssh", "4", "10")
	if !reflect.DeepEqual(journalArgs(q), []string{"--output=json", "-n", "10", "--no-pager", "--unit=ssh.service", "--priority=4"}) {
		t.Fatal(journalArgs(q))
	}
}

func TestJournalDegrades(t *testing.T) {
	r := collectJournal(context.Background(), JournalQuery{Lines: 1}, func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("permission denied") })
	if r.Lines == nil || r.Warning == "" {
		t.Fatalf("bad degradation: %#v", r)
	}
}

func TestJournalByteBounds(t *testing.T) {
	big := strings.Repeat("é", 3000) // 6000 bytes, cut on a rune boundary
	lines := []JournalLine{{Message: "oldest"}, {Message: big}, {Message: strings.Repeat("x", 100)}, {Message: "newest"}}
	got, truncated := boundJournal(lines, 4096, 4210)
	if !truncated || len(got) != 3 || got[2].Message != "newest" {
		t.Fatalf("truncated=%v %d", truncated, len(got))
	}
	if !utf8.ValidString(got[0].Message) || len(got[0].Message) > 4096+len("…") || !strings.HasSuffix(got[0].Message, "…") {
		t.Fatalf("bad cut: %d", len(got[0].Message))
	}
	if got, truncated := boundJournal([]JournalLine{{Message: "a"}, {Message: "b"}}, 10, 10); truncated || len(got) != 2 {
		t.Fatal("small journal changed")
	}
}

func TestUnitJournalIsBounded(t *testing.T) {
	var raw strings.Builder
	for i := 0; i < 300; i++ {
		raw.WriteString(`{"__REALTIME_TIMESTAMP":"1000","_SYSTEMD_UNIT":"home-backup.service","MESSAGE":"` + strings.Repeat("m", 1000) + `"}` + "\n")
	}
	q, err := NewJournalQuery("home-backup", "", "300")
	if err != nil {
		t.Fatal(err)
	}
	var argv []string
	r := collectJournal(context.Background(), q, func(_ context.Context, name string, args ...string) ([]byte, error) {
		argv = append([]string{name}, args...)
		return []byte(raw.String()), nil
	})
	if !reflect.DeepEqual(argv, []string{"journalctl", "--output=json", "-n", "300", "--no-pager", "--unit=home-backup.service"}) {
		t.Fatal(argv)
	}
	size := 0
	for _, l := range r.Lines {
		size += len(l.Message)
	}
	if !r.Truncated || size > 64<<10 || len(r.Lines) != 65 {
		t.Fatalf("truncated=%v size=%d lines=%d", r.Truncated, size, len(r.Lines))
	}
}

func TestTailBufferKeepsNewest(t *testing.T) {
	b := &tailBuffer{limit: 8}
	for _, p := range []string{"abc", "defgh", "ij", strings.Repeat("z", 3)} {
		_, _ = b.Write([]byte(p))
	}
	if string(b.data) != "fghijzzz" {
		t.Fatal(string(b.data))
	}
	_, _ = b.Write([]byte("0123456789"))
	if string(b.data) != "23456789" {
		t.Fatal(string(b.data))
	}
}
