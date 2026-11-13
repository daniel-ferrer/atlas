package collect

import (
	"context"
	"errors"
	"testing"
)

func TestParseAndMergeUnits(t *testing.T) {
	tests := []struct {
		name, list, show string
		want             int64
		mem              bool
	}{
		{"active", `[{"unit":"ssh.service","description":"SSH","active":"active","sub":"running"}]`, "MemoryCurrent=4096\nId=ssh.service\nActiveEnterTimestamp=@1700000000\n", 1700000000000, true},
		{"unset", `[{"unit":"cron.service","description":"Cron","active":"inactive","sub":"dead"}]`, "Id=cron.service\nActiveEnterTimestamp=\nMemoryCurrent=[not set]\n", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			units, err := parseListUnits([]byte(tt.list))
			if err != nil {
				t.Fatal(err)
			}
			mergeUnitDetails(units, parseShowBlocks([]byte(tt.show)))
			if len(units) != 1 || units[0].Name == "" {
				t.Fatalf("bad mapping: %#v", units)
			}
			if tt.want != 0 && (units[0].Since == nil || *units[0].Since != tt.want) {
				t.Fatalf("since: %#v", units[0].Since)
			}
			if (units[0].MemBytes != nil) != tt.mem {
				t.Fatalf("memory: %#v", units[0].MemBytes)
			}
		})
	}
}

func TestUnitsDegrades(t *testing.T) {
	r := collectUnits(context.Background(), func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("denied") })
	if r.Units == nil || len(r.Units) != 0 || r.Warning == "" {
		t.Fatalf("bad degradation: %#v", r)
	}
}
