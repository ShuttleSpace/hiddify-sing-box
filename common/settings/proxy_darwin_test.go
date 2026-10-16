package settings

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/shell"
)

func TestParseProxyOutput(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		enabled, server, port := parseProxyOutput("Enabled: Yes\nServer: 127.0.0.1\nPort: 12334\nAuthenticated Proxy Enabled: 0\n")
		if !enabled || server != "127.0.0.1" || port != 12334 {
			t.Fatalf("unexpected parse: %v %q %d", enabled, server, port)
		}
	})

	t.Run("disabled with leftover address", func(t *testing.T) {
		// This is the shape networksetup leaves after -setwebproxystate off: the
		// switch is off but the host is still recorded, which is exactly what the
		// reported bug looked like in System Settings.
		enabled, server, port := parseProxyOutput("Enabled: No\nServer: ::1\nPort: 12334\n")
		if enabled {
			t.Fatal("entry must not be reported as enabled")
		}
		if server != "::1" || port != 12334 {
			t.Fatalf("leftover address must still be parsed: %q %d", server, port)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if enabled, _, _ := parseProxyOutput("** Error: The parameters were not valid."); enabled {
			t.Fatal("garbage must not parse as enabled")
		}
	})
}

func TestDarwinProxyStatePointsTo(t *testing.T) {
	addr := M.ParseSocksaddrHostPort("127.0.0.1", 12334)

	t.Run("web entry is ours", func(t *testing.T) {
		state := darwinProxyState{webEnabled: true, webServer: "127.0.0.1", webPort: 12334}
		if !state.pointsTo(addr) {
			t.Fatal("expected the web entry to be recognised as ours")
		}
	})

	t.Run("secure entry is ours", func(t *testing.T) {
		state := darwinProxyState{secureEnabled: true, secureServer: "127.0.0.1", securePort: 12334}
		if !state.pointsTo(addr) {
			t.Fatal("expected the secure entry to be recognised as ours")
		}
	})

	t.Run("disabled entry is never ours", func(t *testing.T) {
		state := darwinProxyState{webEnabled: false, webServer: "127.0.0.1", webPort: 12334}
		if state.pointsTo(addr) {
			t.Fatal("a switched-off entry must not be reported as a live write of ours")
		}
	})

	t.Run("another tool's port is not ours", func(t *testing.T) {
		state := darwinProxyState{webEnabled: true, webServer: "127.0.0.1", webPort: 7888}
		if state.pointsTo(addr) {
			t.Fatal("a different port belongs to another tool and must survive our cleanup")
		}
	})

	t.Run("another tool's host is not ours", func(t *testing.T) {
		state := darwinProxyState{webEnabled: true, webServer: "::1", webPort: 12334}
		if state.pointsTo(addr) {
			t.Fatal("a different host is not the write update0 performs, so it must re-apply instead of skipping")
		}
	})
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1":   true,
		"::1":         true,
		"127.0.0.53":  true,
		"localhost":   true,
		"LocalHost":   true,
		"0.0.0.0":     false,
		"::":          false,
		"192.168.1.1": false,
		"":            false,
		"not a host":  false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// holdsOurListener is what decides what gets cleaned, so it has to recognise what
// older builds wrote. Those recorded ::1 on our port and left it behind switched
// off, which kept System Settings showing a live proxy after we disconnected.
func TestDarwinProxyStateHoldsOurListener(t *testing.T) {
	addr := M.ParseSocksaddrHostPort("127.0.0.1", 12334)

	t.Run("live write of ours", func(t *testing.T) {
		state := darwinProxyState{webEnabled: true, webServer: "127.0.0.1", webPort: 12334}
		if !state.holdsOurListener(addr) {
			t.Fatal("our own live entry must be released")
		}
	})

	t.Run("legacy ::1 residue switched off", func(t *testing.T) {
		state := darwinProxyState{
			webEnabled: false, webServer: "::1", webPort: 12334,
			secureEnabled: false, secureServer: "::1", securePort: 12334,
		}
		if !state.holdsOurListener(addr) {
			t.Fatal("residue an older build left behind must still be claimed")
		}
	})

	t.Run("another tool's port is not ours", func(t *testing.T) {
		state := darwinProxyState{webEnabled: true, webServer: "::1", webPort: 7888}
		if state.holdsOurListener(addr) {
			t.Fatal("a different port belongs to another tool and must survive our cleanup")
		}
	})

	t.Run("non-loopback host on our port is not ours", func(t *testing.T) {
		state := darwinProxyState{webEnabled: true, webServer: "192.168.1.1", webPort: 12334}
		if state.holdsOurListener(addr) {
			t.Fatal("only a loopback address can be our own listener")
		}
	})

	t.Run("socks entry alone is enough", func(t *testing.T) {
		state := darwinProxyState{socksEnabled: true, socksServer: "127.0.0.1", socksPort: 12334}
		if !state.holdsOurListener(addr) {
			t.Fatal("a socks entry on our port makes the service ours")
		}
	})
}

func TestDarwinProxyStateRoutesThroughUs(t *testing.T) {
	addr := M.ParseSocksaddrHostPort("127.0.0.1", 12334)

	t.Run("live write of ours", func(t *testing.T) {
		state := darwinProxyState{webEnabled: true, webServer: "127.0.0.1", webPort: 12334}
		if !state.routesThroughUs(addr) {
			t.Fatal("a switched-on entry on our port still steals traffic and must count")
		}
	})

	t.Run("released entry is not traffic", func(t *testing.T) {
		// networksetup keeps host and port after the switch goes off, so holding
		// our listener is not the same as still routing through it.
		state := darwinProxyState{webEnabled: false, webServer: "127.0.0.1", webPort: 12334}
		if !state.holdsOurListener(addr) {
			t.Fatal("fixture must still be recognised as ours")
		}
		if state.routesThroughUs(addr) {
			t.Fatal("a switched-off entry routes nothing")
		}
	})

	t.Run("another tool's port is not ours", func(t *testing.T) {
		state := darwinProxyState{webEnabled: true, webServer: "127.0.0.1", webPort: 7888}
		if state.routesThroughUs(addr) {
			t.Fatal("a different port belongs to another tool")
		}
	})
}

func TestListNetworkServices(t *testing.T) {
	services, err := listNetworkServices()
	if err != nil {
		t.Skipf("networksetup unavailable: %v", err)
	}
	if len(services) == 0 {
		t.Fatal("expected at least one network service")
	}
	for _, service := range services {
		if strings.HasPrefix(service, "An asterisk") {
			t.Fatalf("legend leaked into the service list: %q", service)
		}
		if service == "" {
			t.Fatal("empty service name")
		}
	}
}

// A renamed service is the whole reason this lookup exists: the service name and
// the hardware port name are separate, editable fields and networksetup rejects
// anything that is not the service name.
const serviceOrderFixture = `An asterisk (*) denotes that a network service is disabled.
(1) My Home Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) USB 10/100/1000 LAN
(Hardware Port: AX88179A, Device: en6)

(*3) * Tailscale
(Hardware Port: io.tailscale.ipn.macsys, Device: )

(4) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

`

func TestParseServiceNameForDevice(t *testing.T) {
	for name, tc := range map[string]struct{ device, want string }{
		"renamed service":       {"en0", "My Home Wi-Fi"},
		"renamed over hardware": {"en6", "USB 10/100/1000 LAN"},
		"bridge":                {"bridge0", "Thunderbolt Bridge"},
		"unknown device":        {"utun7", ""},
		// A deviceless service, the shape Tailscale installs, has nothing to be
		// looked up by and must not satisfy an empty query either.
		"empty device": {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := parseServiceNameForDevice(serviceOrderFixture, tc.device); got != tc.want {
				t.Fatalf("parseServiceNameForDevice(%q) = %q, want %q", tc.device, got, tc.want)
			}
		})
	}
}

func TestParseServiceOrderName(t *testing.T) {
	for line, want := range map[string]string{
		"(1) My Home Wi-Fi": "My Home Wi-Fi",
		"(*3) * Tailscale":  "Tailscale",
		"An asterisk (*) denotes that a network service is disabled.": "",
		"(Hardware Port: Wi-Fi, Device: en0)":                         "",
		"(3)":                                                         "",
		"":                                                            "",
	} {
		got, _ := parseServiceOrderName(line)
		if got != want {
			t.Errorf("parseServiceOrderName(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestParseServiceOrderDetail(t *testing.T) {
	for line, want := range map[string]string{
		"(Hardware Port: Wi-Fi, Device: en0)":                "en0",
		"(Hardware Port: io.tailscale.ipn.macsys, Device: )": "",
		"(Hardware Port: Wi-Fi, Device: )":                   "",
		"(Hardware Port: Wi-Fi, Device: en0":                 "",
		"(1) My Home Wi-Fi":                                  "",
	} {
		got, _ := parseServiceOrderDetail(line)
		if got != want {
			t.Errorf("parseServiceOrderDetail(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestServiceNameForDeviceResolvesTheLiveSystem(t *testing.T) {
	services, err := listNetworkServices()
	if err != nil {
		t.Skipf("networksetup unavailable: %v", err)
	}
	order, err := shell.Exec("networksetup", "-listnetworkserviceorder").ReadOutput()
	if err != nil {
		t.Skipf("networksetup unavailable: %v", err)
	}
	// Every entry the parser produces has to be a name networksetup accepts,
	// otherwise we would be handing it the same hardware port name as before.
	accepted := map[string]bool{}
	for _, service := range services {
		accepted[service] = true
	}
	for _, line := range strings.Split(string(order), "\n") {
		device, ok := parseServiceOrderDetail(strings.TrimSpace(line))
		if !ok {
			continue
		}
		serviceName, err := serviceNameForDevice(device)
		if err != nil {
			t.Fatalf("serviceNameForDevice(%q): %v", device, err)
		}
		if !accepted[serviceName] {
			t.Errorf("device %q resolved to %q, which is not a network service name", device, serviceName)
		}
	}
}

func TestRestoreScriptIsValidShell(t *testing.T) {
	script := (&DarwinSystemProxy{}).restoreScript("Wi-Fi", &darwinProxyState{})
	path := filepath.Join(t.TempDir(), "restore.sh")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/bin/sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("generated script is not valid shell: %v\n%s", err, output)
	}
}

func TestRestoreScriptRestoresCapturedState(t *testing.T) {
	state := &darwinProxyState{
		webEnabled: true, webServer: "127.0.0.1", webPort: 7888,
		secureEnabled: true, secureServer: "127.0.0.1", securePort: 7888,
		socksEnabled: true, socksServer: "127.0.0.1", socksPort: 7888,
	}
	script := (&DarwinSystemProxy{}).restoreScript("Wi-Fi", state)
	for _, want := range []string{
		"'-setwebproxy' 'Wi-Fi' '127.0.0.1' '7888'",
		"'-setwebproxystate' 'Wi-Fi' 'on'",
		"'-setsecurewebproxy' 'Wi-Fi' '127.0.0.1' '7888'",
		"'-setsocksfirewallproxy' 'Wi-Fi' '127.0.0.1' '7888'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("restore script is missing %q", want)
		}
	}
}

func TestRestoreScriptDisablesWhenPreviousWasOff(t *testing.T) {
	script := (&DarwinSystemProxy{}).restoreScript("Wi-Fi", &darwinProxyState{})
	for _, want := range []string{
		"'-setwebproxystate' 'Wi-Fi' 'off'",
		"'-setsecurewebproxystate' 'Wi-Fi' 'off'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("restore script is missing %q", want)
		}
	}
	// An off entry has no host to restore, so no proxy command may be emitted.
	if strings.Contains(script, "'-setwebproxy' 'Wi-Fi'") {
		t.Error("an entry that was off must not be given a host back")
	}
}

// The pid is supplied by startWatchdog, not by restoreScript itself: restoreScript
// only builds the payload of the guard. This locks in that separation so a future
// edit cannot silently drop the wait from the composed command.
func TestRestoreScriptIsOnlyThePayload(t *testing.T) {
	script := (&DarwinSystemProxy{}).restoreScript("Wi-Fi", &darwinProxyState{})
	if strings.Contains(script, "kill -0") {
		t.Fatal("restoreScript must not embed the owner wait, which startWatchdog composes")
	}
}

func TestShellQuote(t *testing.T) {
	for input, want := range map[string]string{
		"Wi-Fi":       "'Wi-Fi'",
		"127.0.0.1":   "'127.0.0.1'",
		"::1":         "'::1'",
		"it's":        `'it'"'"'s'`,
		"a b; rm -rf": "'a b; rm -rf'",
	} {
		if got := shellQuote(input); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestShellCommandQuotesEveryArgument(t *testing.T) {
	got := shellCommand("networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1")
	if strings.Count(got, "'") != 6 {
		t.Fatalf("every argument must be quoted, got %q", got)
	}
}

// Sweeps the live system, so it only runs when nothing is connected: Disable would
// otherwise pull the proxy out from under a running session.
func TestDisableOwnedServicesLeavesOtherToolsAlone(t *testing.T) {
	proxy := &DarwinSystemProxy{
		serverAddr:   M.ParseSocksaddrHostPort("127.0.0.1", 12334),
		supportSOCKS: true,
	}
	services, err := listNetworkServices()
	if err != nil {
		t.Skipf("networksetup unavailable: %v", err)
	}
	for _, service := range services {
		if state, err := readDarwinProxyState(service); err == nil {
			if state.routesThroughUs(proxy.serverAddr) {
				t.Skipf("service %q is routing through us, a session is live", service)
			}
		}
	}
	if err := proxy.disableOwnedServices(); err != nil {
		t.Skipf("networksetup unavailable: %v", err)
	}
	for _, service := range services {
		if state, err := readDarwinProxyState(service); err == nil {
			if state.routesThroughUs(proxy.serverAddr) {
				t.Fatalf("service %q still routes through us after Disable", service)
			}
		}
	}
}

// A service whose entry we own must come back switched off and recorded under the
// host we write today, never the ::1 an older build wrote. networksetup keeps the
// host after the switch goes off, so anything less leaves the residue on screen.
func TestReleaseNormalisesTheRecordedHost(t *testing.T) {
	proxy := &DarwinSystemProxy{
		serverAddr:   M.ParseSocksaddrHostPort("127.0.0.1", 12334),
		supportSOCKS: true,
	}
	state := &darwinProxyState{
		webEnabled: true, webServer: "::1", webPort: 12334,
		secureEnabled: true, secureServer: "::1", securePort: 12334,
		socksEnabled: true, socksServer: "::1", socksPort: 12334,
	}
	if !state.holdsOurListener(proxy.serverAddr) {
		t.Fatal("fixture must be recognised as ours")
	}
	want := [][]string{
		{"networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", "12334"},
		{"networksetup", "-setwebproxystate", "Wi-Fi", "off"},
		{"networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "12334"},
		{"networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"},
		{"networksetup", "-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "12334"},
		{"networksetup", "-setsocksfirewallproxystate", "Wi-Fi", "off"},
	}
	if got := proxy.releaseCommands("Wi-Fi", state); !reflect.DeepEqual(got, want) {
		t.Fatalf("release commands:\n got %v\nwant %v", got, want)
	}
}

// Residue an older build left is already switched off. Only the recorded host needs
// fixing there, and the switch command is skipped rather than run for nothing.
func TestReleaseRewritesResidueWithoutRetogglingIt(t *testing.T) {
	proxy := &DarwinSystemProxy{
		serverAddr:   M.ParseSocksaddrHostPort("127.0.0.1", 12334),
		supportSOCKS: true,
	}
	state := &darwinProxyState{
		webEnabled: false, webServer: "::1", webPort: 12334,
		secureEnabled: false, secureServer: "::1", securePort: 12334,
		socksEnabled: false, socksServer: "::1", socksPort: 12334,
	}
	want := [][]string{
		{"networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", "12334"},
		{"networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "12334"},
		{"networksetup", "-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "12334"},
	}
	if got := proxy.releaseCommands("Wi-Fi", state); !reflect.DeepEqual(got, want) {
		t.Fatalf("release commands:\n got %v\nwant %v", got, want)
	}
}

// The sweeper reaches every service, including ones that merely hold residue, so it
// must not switch off a neighbouring entry belonging to another tool.
func TestReleaseLeavesNeighbouringEntriesAlone(t *testing.T) {
	proxy := &DarwinSystemProxy{
		serverAddr:   M.ParseSocksaddrHostPort("127.0.0.1", 12334),
		supportSOCKS: true,
	}
	state := &darwinProxyState{
		webEnabled: false, webServer: "::1", webPort: 12334,
		secureEnabled: false, secureServer: "127.0.0.1", securePort: 7888,
		socksEnabled: true, socksServer: "127.0.0.1", socksPort: 7888,
	}
	want := [][]string{
		{"networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", "12334"},
	}
	if got := proxy.releaseCommands("Wi-Fi", state); !reflect.DeepEqual(got, want) {
		t.Fatalf("release must leave the 7888 entries untouched:\n got %v\nwant %v", got, want)
	}
}
