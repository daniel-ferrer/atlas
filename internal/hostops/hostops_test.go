package hostops

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// aptShow mirrors `systemctl show --property=...` for the shipped unit
// (systemd 257): each ExecStart command is printed on its own line, and
// properties with no value, like ExecStartPre, are omitted.
const aptShow = `Type=oneshot
RemainAfterExit=no
ExecStart={ path=/usr/bin/apt-get ; argv[]=/usr/bin/apt-get update ; ignore_errors=no ; start_time=[Sat 2026-10-17 03:34:03 CDT] ; stop_time=[Sat 2026-10-17 03:34:09 CDT] ; pid=1715345 ; code=exited ; status=0 }
ExecStart={ path=/usr/bin/apt-get ; argv[]=/usr/bin/apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade ; ignore_errors=no ; start_time=[Sat 2026-10-17 03:34:09 CDT] ; stop_time=[Sat 2026-10-17 03:35:40 CDT] ; pid=1715347 ; code=exited ; status=0 }
Environment=DEBIAN_FRONTEND=noninteractive
User=root
Id=atlas-apt-upgrade.service
LoadState=loaded
ActiveState=inactive
`

func aptProperties() map[string]string { return Properties(aptShow) }
func TestReviewedAptUnitOnly(t *testing.T) {
	p := aptProperties()
	if err := ValidateApt(p, p["Id"]); err != nil {
		t.Fatal(err)
	}
	// A never-run unit renders without timestamps or a pid.
	fresh := strings.NewReplacer("start_time=[Sat 2026-10-17 03:34:03 CDT]", "start_time=[n/a]", "start_time=[Sat 2026-10-17 03:34:09 CDT]", "start_time=[n/a]", "code=exited ; status=0", "code=(null) ; status=0/0").Replace(aptShow)
	if err := ValidateApt(Properties(fresh), "atlas-apt-upgrade.service"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, value string }{
		{"Id", "alias.service"}, {"LoadState", "not-found"}, {"Type", "simple"}, {"User", "demo"}, {"RemainAfterExit", "yes"}, {"Environment", "DEBIAN_FRONTEND=noninteractive APT_CONFIG=/tmp/evil"}, {"EnvironmentFiles", "/tmp/env"}, {"ExecStartPre", "anything"}, {"ExecStartPost", "anything"}, {"ExecCondition", "anything"}, {"ExecStop", "anything"}, {"ExecStopPost", "anything"},
		{"ExecStart", strings.ReplaceAll(p["ExecStart"], " upgrade", " dist-upgrade")}, {"ExecStart", strings.ReplaceAll(p["ExecStart"], "ignore_errors=no", "ignore_errors=yes")}, {"ExecStart", strings.ReplaceAll(p["ExecStart"], "/usr/bin/apt-get", "/tmp/apt-get")}, {"ExecStart", p["ExecStart"] + p["ExecStart"]}, {"ExecStart", "garbage"}, {"ExecStart", strings.Split(p["ExecStart"], "\n")[0]}, {"ExecStart", strings.ReplaceAll(p["ExecStart"], "\n", " ; ")},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			p := aptProperties()
			p[tc.key] = tc.value
			if ValidateApt(p, p["Id"]) == nil && tc.key != "Id" {
				t.Fatal("accepted drift")
			}
			if tc.key == "Id" && ValidateApt(p, "atlas-apt-upgrade.service") == nil {
				t.Fatal("accepted alias")
			}
		})
	}
	// Drift as systemctl would render it: extra lines, never overwritten away.
	upgrade := strings.Split(p["ExecStart"], "\n")[1]
	for name, text := range map[string]string{
		"third ExecStart":  aptShow + "ExecStart=" + upgrade + "\n",
		"ExecStartPre":     aptShow + "ExecStartPre={ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n",
		"repeated Id":      aptShow + "Id=other.service\n",
		"second env line":  aptShow + "Environment=APT_CONFIG=/tmp/evil\n",
		"EnvironmentFiles": aptShow + "EnvironmentFiles=/tmp/env (ignore_errors=no)\n",
	} {
		if ValidateApt(Properties(text), "atlas-apt-upgrade.service") == nil {
			t.Fatal("accepted drift:", name)
		}
	}
}
func TestSystemdAndProcParsers(t *testing.T) {
	p := Properties("Id=demo.service\nNames=demo.service alias.service\nEnvironment=A=B\n")
	if p["Id"] != "demo.service" || p["Environment"] != "A=B" {
		t.Fatal(p)
	}
	if p := Properties("ExecStart={ a }\nExecStart={ b }\n"); p["ExecStart"] != "{ a }\n{ b }" {
		t.Fatalf("%q", p["ExecStart"])
	}
	if got := CgroupUnits("0::/system.slice/otto.service/worker\n1:name=systemd:/system.slice/atlas.service\n0::/otto.service-impostor"); !slices.Equal(got, []string{"otto.service", "atlas.service"}) {
		t.Fatal(got)
	}
	flags, err := StatFlags("123 (name with ) spaces) S 1 2 3 4 5 2097152 0 0")
	if err != nil || flags != 2097152 {
		t.Fatal(flags, err)
	}
	for _, bad := range []string{"", "123 x", "123 (x) S 1", "123 (x) S 1 2 3 4 5 nope"} {
		if _, err := StatFlags(bad); err == nil {
			t.Fatal(bad)
		}
	}
}
func TestBoundedUTF8Output(t *testing.T) {
	var tail Tail
	for range 1000 {
		_, _ = tail.Write([]byte(strings.Repeat("€", 100)))
	}
	if len(tail.String()) > 65536 {
		t.Fatal("unbounded buffer")
	}
	s := TailText(tail.String(), 4000)
	if len(s) > 4000 || !utf8.ValidString(s) || !strings.HasSuffix(s, "€") {
		t.Fatal("invalid output tail")
	}
	s = TailText("bad\xffbytes", 4000)
	if !utf8.ValidString(s) {
		t.Fatal("invalid utf8")
	}
}
