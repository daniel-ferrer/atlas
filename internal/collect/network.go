package collect

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	gn "github.com/shirou/gopsutil/v4/net"
)

type NetworkInterface struct {
	Name      string   `json:"name"`
	Addrs     []string `json:"addrs"`
	MAC       string   `json:"mac"`
	SpeedMbps *int64   `json:"speedMbps"`
	RxBytes   uint64   `json:"rxBytes"`
	TxBytes   uint64   `json:"txBytes"`
	RxErrs    uint64   `json:"rxErrs"`
	TxErrs    uint64   `json:"txErrs"`
}
type ListeningPort struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Process string `json:"process"`
	Pid     int    `json:"pid"`
	Scope   string `json:"scope"`
}
type Connection struct {
	Peer    string `json:"peer"`
	Port    int    `json:"port"`
	Process string `json:"process"`
	State   string `json:"state"`
}
type TailscalePeer struct {
	Name     string `json:"name"`
	IP       string `json:"ip"`
	OS       string `json:"os"`
	LastSeen *int64 `json:"lastSeen"`
	Route    string `json:"route"`
	Online   bool   `json:"online"`
}
type NetworkResult struct {
	Interfaces     []NetworkInterface `json:"interfaces"`
	ListeningPorts []ListeningPort    `json:"listeningPorts"`
	Connections    []Connection       `json:"connections"`
	TailscalePeers []TailscalePeer    `json:"tailscalePeers"`
	Warning        string             `json:"warning,omitempty"`
}

func Network(ctx context.Context) NetworkResult {
	return collectNetworkWithInterfaces(ctx, execCommand, "/sys/class/net", collectInterfaces)
}
func collectNetwork(ctx context.Context, run commandRunner, sysRoot string) NetworkResult {
	return collectNetworkWithInterfaces(ctx, run, sysRoot, collectInterfaces)
}

type interfaceCollector func(context.Context, string) ([]NetworkInterface, error)

func collectNetworkWithInterfaces(ctx context.Context, run commandRunner, sysRoot string, interfaces interfaceCollector) NetworkResult {
	r := NetworkResult{Interfaces: []NetworkInterface{}, ListeningPorts: []ListeningPort{}, Connections: []Connection{}, TailscalePeers: []TailscalePeer{}}
	var warnings []string
	ifaces, err := interfaces(ctx, sysRoot)
	if err != nil {
		warnings = append(warnings, warningFor(err, "network interfaces", "network interfaces unavailable — grant access to /proc/net and /sys/class/net"))
	} else {
		r.Interfaces = ifaces
	}
	if raw, e := run(ctx, "ss", "-tulpnH"); e != nil {
		warnings = append(warnings, warningFor(e, "ss", "listening ports unavailable — install iproute2 and permit the atlas user to run ss"))
	} else {
		r.ListeningPorts = parseListeningPorts(raw)
		attributed := false
		for _, p := range r.ListeningPorts {
			attributed = attributed || p.Pid != 0
		}
		if len(r.ListeningPorts) > 0 && !attributed {
			warnings = append(warnings, "listening port process attribution unavailable — grant root access or a narrowly scoped sudoers entry for ss")
		}
	}
	if raw, e := run(ctx, "ss", "-tnpH"); e != nil {
		warnings = append(warnings, warningFor(e, "ss connections", "connections unavailable — install iproute2 and permit the atlas user to run ss"))
	} else {
		r.Connections = parseConnections(raw)
		if len(r.Connections) > 200 {
			r.Connections = r.Connections[:200]
		}
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if raw, e := run(tctx, "tailscale", "status", "--json"); e != nil {
		warnings = append(warnings, warningFor(e, "tailscale", "tailscale peers unavailable — install tailscale and permit access to its local daemon"))
	} else if peers, e := parseTailscaleStatus(raw); e != nil {
		warnings = append(warnings, "tailscale returned invalid JSON")
	} else {
		r.TailscalePeers = peers
	}
	r.Warning = joinWarnings(warnings...)
	return r
}
func collectInterfaces(ctx context.Context, sysRoot string) ([]NetworkInterface, error) {
	stats, e := gn.InterfacesWithContext(ctx)
	if e != nil {
		return nil, e
	}
	io, e := gn.IOCountersWithContext(ctx, true)
	if e != nil {
		return nil, e
	}
	by := map[string]gn.IOCountersStat{}
	for _, x := range io {
		by[x.Name] = x
	}
	out := make([]NetworkInterface, 0, len(stats))
	for _, x := range stats {
		addrs := make([]string, 0, len(x.Addrs))
		for _, a := range x.Addrs {
			addrs = append(addrs, a.Addr)
		}
		n := by[x.Name]
		var speed *int64
		if b, e := os.ReadFile(filepath.Join(sysRoot, x.Name, "speed")); e == nil {
			if v, e := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); e == nil && v > 0 {
				speed = &v
			}
		}
		out = append(out, NetworkInterface{Name: x.Name, Addrs: addrs, MAC: x.HardwareAddr, SpeedMbps: speed, RxBytes: n.BytesRecv, TxBytes: n.BytesSent, RxErrs: n.Errin, TxErrs: n.Errout})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type ssRow struct{ proto, state, local, peer, users string }

func splitSSRow(line string) (ssRow, bool) {
	f := strings.Fields(line)
	if len(f) < 5 {
		return ssRow{}, false
	}
	off := 0
	proto := "tcp"
	if f[0] == "tcp" || f[0] == "udp" {
		proto = f[0]
		off = 1
	}
	if len(f) < off+5 {
		return ssRow{}, false
	}
	return ssRow{proto: proto, state: f[off], local: f[off+3], peer: f[off+4], users: strings.Join(f[off+5:], " ")}, true
}

var userRE = regexp.MustCompile(`\(\("([^" ]+)".*,pid=([0-9]+)`)

func endpoint(s string) (string, int) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return strings.Trim(s, "[]"), 0
	}
	host := s[:i]
	if z := strings.Index(host, "%"); z >= 0 {
		host = host[:z]
	}
	host = strings.Trim(host, "[]")
	p, _ := strconv.Atoi(s[i+1:])
	return host, p
}
func processFrom(users string) (string, int) {
	m := userRE.FindStringSubmatch(users)
	if len(m) == 0 {
		return "", 0
	}
	p, _ := strconv.Atoi(m[2])
	return m[1], p
}
func parseListeningPorts(raw []byte) []ListeningPort {
	out := []ListeningPort{}
	for _, line := range strings.Split(string(raw), "\n") {
		r, ok := splitSSRow(line)
		if !ok || !(r.state == "LISTEN" || r.state == "UNCONN") {
			continue
		}
		a, p := endpoint(r.local)
		if p == 0 {
			continue
		}
		name, pid := processFrom(r.users)
		out = append(out, ListeningPort{Port: p, Proto: r.proto, Process: name, Pid: pid, Scope: classifyScope(a)})
	}
	return out
}

// The security view conservatively treats every non-loopback/non-tailnet bind as public.
func classifyScope(addr string) string {
	addr = strings.Trim(addr, "[]")
	if addr == "" || addr == "*" || addr == "0.0.0.0" || addr == "::" {
		return "public"
	}
	ip := net.ParseIP(addr)
	if ip != nil && ip.IsLoopback() {
		return "local"
	}
	_, v4, _ := net.ParseCIDR("100.64.0.0/10")
	_, v6, _ := net.ParseCIDR("fd7a:115c:a1e0::/48")
	if ip != nil && (v4.Contains(ip) || v6.Contains(ip)) {
		return "tailnet"
	}
	return "public"
}

// ss supplies process names without gopsutil's expensive, permission-limited /proc/*/fd walk.
func parseConnections(raw []byte) []Connection {
	out := []Connection{}
	for _, line := range strings.Split(string(raw), "\n") {
		r, ok := splitSSRow(line)
		if !ok || !(r.state == "ESTAB" || r.state == "ESTABLISHED") {
			continue
		}
		host, p := endpoint(r.peer)
		name, _ := processFrom(r.users)
		out = append(out, Connection{Peer: host, Port: p, Process: name, State: r.state})
	}
	return out
}
func parseTailscaleStatus(raw []byte) ([]TailscalePeer, error) {
	var root struct {
		Peer map[string]struct {
			HostName, DNSName, OS, LastSeen, CurAddr, Relay string
			TailscaleIPs                                    []string
			Online                                          bool
		}
	}
	if e := json.Unmarshal(raw, &root); e != nil {
		return nil, e
	}
	out := []TailscalePeer{}
	for _, p := range root.Peer {
		name := p.HostName
		if name == "" {
			name = strings.TrimSuffix(p.DNSName, ".")
		}
		ip := ""
		if len(p.TailscaleIPs) > 0 {
			ip = p.TailscaleIPs[0]
		}
		route := ""
		if p.CurAddr != "" {
			route = "direct"
		} else if p.Relay != "" {
			route = "relay:" + p.Relay
		}
		var seen *int64
		if t, e := time.Parse(time.RFC3339, p.LastSeen); e == nil && !t.IsZero() && t.Year() > 1 {
			v := t.UnixMilli()
			seen = &v
		}
		out = append(out, TailscalePeer{Name: name, IP: ip, OS: p.OS, LastSeen: seen, Route: route, Online: p.Online})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
