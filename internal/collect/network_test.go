package collect

import (
	"context"
	"errors"
	"testing"
)

func TestClassifyScope(t *testing.T) {
	tests := map[string]string{"0.0.0.0": "public", "*": "public", "::": "public", "127.0.0.1": "local", "::1": "local", "100.101.102.103": "tailnet", "192.168.1.2": "public", "fe80::1": "public", "fd7a:115c:a1e0::2": "tailnet"}
	for in, want := range tests {
		if got := classifyScope(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
	if host, port := endpoint("[fe80::1]%enp3s0:546"); host != "fe80::1" || port != 546 {
		t.Fatalf("zoned endpoint = %q:%d", host, port)
	}
}
func TestParseSSFixtures(t *testing.T) {
	raw := []byte("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=12,fd=3))\nudp UNCONN 0 0 100.101.102.103:53 *:*\nLISTEN 0 10 [::1]:8080 [::]:* users:((\"app\",pid=7,fd=4))\n")
	p := parseListeningPorts(raw)
	if len(p) != 3 || p[0].Proto != "tcp" || p[0].Pid != 12 || p[1].Scope != "tailnet" || p[2].Scope != "local" {
		t.Fatalf("ports: %+v", p)
	}
	c := parseConnections([]byte("ESTAB 0 0 10.0.0.1:55 8.8.8.8:443 users:((\"curl\",pid=9,fd=1))\n"))
	if len(c) != 1 || c[0].Peer != "8.8.8.8" || c[0].Process != "curl" {
		t.Fatalf("connections: %+v", c)
	}
}
func TestTailscaleFixture(t *testing.T) {
	raw := []byte(`{"Peer":{"a":{"HostName":"alpha","OS":"linux","TailscaleIPs":["100.64.0.2"],"Online":true,"LastSeen":"0001-01-01T00:00:00Z","CurAddr":"1.2.3.4:1"},"b":{"DNSName":"beta.ts.net.","OS":"darwin","TailscaleIPs":["100.64.0.3"],"LastSeen":"2024-01-02T03:04:05Z","Relay":"dfw"}}}`)
	p, e := parseTailscaleStatus(raw)
	if e != nil || len(p) != 2 || p[0].LastSeen != nil || p[0].Route != "direct" || p[1].LastSeen == nil || p[1].Route != "relay:dfw" {
		t.Fatalf("peers=%+v err=%v", p, e)
	}
}
func TestNetworkDegradesAndWarnsOnNoAttribution(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ss" && len(args) > 0 && args[0] == "-tulpnH" {
			return []byte("tcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\n"), nil
		}
		return nil, errors.New("missing")
	}
	r := collectNetworkWithInterfaces(context.Background(), run, t.TempDir(), func(context.Context, string) ([]NetworkInterface, error) { return nil, errors.New("denied") })
	if len(r.ListeningPorts) != 1 || r.Warning == "" || r.TailscalePeers == nil {
		t.Fatalf("result: %+v", r)
	}
}
