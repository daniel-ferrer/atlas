package collect

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSmartFixtures(t *testing.T) {
	ata := []byte(`{"model_name":"ATA","smart_status":{"passed":true},"temperature":{"current":61},"power_on_time":{"hours":99},"ata_smart_attributes":{"table":[{"id":5,"value":100,"raw":{"value":2}},{"id":177,"value":70,"raw":{"value":0}},{"id":241,"value":100,"raw":{"value":10}}]}}`)
	d, e := parseSmartctl(ata)
	if e != nil || d.State != "warn" || d.Reallocated != 2 || d.WearPercent == nil || *d.WearPercent != 30 || d.Written == nil || *d.Written != 5120 {
		t.Fatalf("ATA: %+v %v", d, e)
	}
	nvme := []byte(`{"model_name":"NVMe","smart_status":{"passed":true},"nvme_smart_health_information_log":{"temperature":40,"percentage_used":9,"power_on_hours":50,"data_units_written":2}}`)
	d, e = parseSmartctl(nvme)
	if e != nil || d.State != "passed" || d.Written == nil || *d.Written != 1024000 {
		t.Fatalf("NVMe: %+v %v", d, e)
	}
	denied := []byte(`{"smartctl":{"exit_status":2,"messages":[{"string":"Permission denied"}]}}`)
	if !smartPermissionDenied(denied, errors.New("exit status 2")) {
		t.Fatal("permission not detected")
	}
}
func TestCollectSmartPermissionDegrades(t *testing.T) {
	var smartArgs []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "lsblk" {
			return []byte("sda disk\n"), nil
		}
		if name != "sudo" {
			t.Fatalf("command = %q, want sudo", name)
		}
		smartArgs = append([]string(nil), args...)
		return []byte(`{"smartctl":{"exit_status":2,"messages":[{"string":"Permission denied"}]}}`), errors.New("exit status 2")
	}
	r := collectSmart(context.Background(), run)
	if len(r.Devices) != 0 || !strings.Contains(r.Warning, "CAP_SYS_RAWIO") {
		t.Fatalf("result: %+v", r)
	}
	if len(smartArgs) != 5 || smartArgs[0] != "-n" || smartArgs[1] == "" || !reflect.DeepEqual(smartArgs[2:], []string{"-j", "-a", "/dev/sda"}) {
		t.Fatalf("smartctl args: %#v", smartArgs)
	}
}

func TestCollectSmartEmptySudoFailuresPreservePermissionWarning(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "sudo denied", err: errors.New("exit status 1")},
		{name: "sudo missing", err: errors.New(`exec: "sudo": executable file not found in $PATH`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := func(_ context.Context, name string, _ ...string) ([]byte, error) {
				if name == "lsblk" {
					return []byte("sda disk\n"), nil
				}
				return nil, tt.err
			}
			r := collectSmart(context.Background(), run)
			if len(r.Devices) != 0 || r.Warning != smartPermissionWarning {
				t.Fatalf("result: %+v", r)
			}
		})
	}
}

func TestCollectSmartViaSudo(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "lsblk" {
			return []byte("nvme0n1 disk\n"), nil
		}
		if name != "sudo" || len(args) != 5 || args[0] != "-n" || args[1] == "" || !reflect.DeepEqual(args[2:], []string{"-j", "-a", "/dev/nvme0n1"}) {
			t.Fatalf("command: %s %#v", name, args)
		}
		return []byte(`{"model_name":"NVMe","smart_status":{"passed":true}}`), nil
	}
	r := collectSmart(context.Background(), run)
	if len(r.Devices) != 1 || r.Devices[0].Device != "/dev/nvme0n1" || r.Warning != "" {
		t.Fatalf("result: %+v", r)
	}
}
