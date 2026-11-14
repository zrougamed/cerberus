package network

import (
	"net"
	"slices"
	"testing"
)

func testIfaces() []net.Interface {
	up := net.FlagUp | net.FlagBroadcast
	return []net.Interface{
		{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
		{Index: 2, Name: "eth0", Flags: up},
		{Index: 3, Name: "wlan0", Flags: up},
		{Index: 4, Name: "docker0", Flags: up},
		{Index: 5, Name: "veth1a2b", Flags: up},
		{Index: 6, Name: "eth1", Flags: net.FlagBroadcast}, // down
	}
}

func names(ifaces []net.Interface) []string {
	out := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		out = append(out, i.Name)
	}
	return out
}

func TestInterfaceFilter_Select(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		spec string
		want []string
	}{
		{name: "empty keeps historical behaviour", spec: "", want: []string{"eth0", "wlan0", "docker0", "veth1a2b"}},
		{name: "whitespace and empty entries ignored", spec: " , ,", want: []string{"eth0", "wlan0", "docker0", "veth1a2b"}},
		{name: "single include", spec: "eth0", want: []string{"eth0"}},
		{name: "glob include", spec: "eth*,wlan*", want: []string{"eth0", "wlan0"}},
		{name: "exclude only", spec: "!docker*, !veth*", want: []string{"eth0", "wlan0"}},
		{name: "exclude wins over include", spec: "eth*,!eth0", want: nil},
		{name: "down interface never selected", spec: "eth1", want: nil},
		{name: "loopback only when included", spec: "lo", want: []string{"lo"}},
		{name: "loopback not matched by exclude-only list", spec: "!eth0", want: []string{"wlan0", "docker0", "veth1a2b"}},
		{name: "unknown name selects nothing", spec: "ens9", want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, err := ParseInterfaceFilter(tc.spec)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.spec, err)
			}
			got := names(f.Select(testIfaces()))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("spec %q: got %v, want %v", tc.spec, got, tc.want)
			}
		})
	}
}

func TestParseInterfaceFilter_Errors(t *testing.T) {
	t.Parallel()
	for _, spec := range []string{"!", "eth0,! ", "eth[", "!wlan["} {
		if _, err := ParseInterfaceFilter(spec); err == nil {
			t.Errorf("expected error for %q", spec)
		}
	}
}
