package settings

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
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
			t.Fatal("a switched-off entry must not be claimed, otherwise Disable would skip it")
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
			t.Fatal("a different host belongs to another tool")
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

func TestDisableOwnedServicesLeavesOtherToolsAlone(t *testing.T) {
	// disableOwnedServices sweeps every service but gates on serviceStillOurs.
	// No service is ours here, so nothing may be touched. This is a read-only
	// pass over the real system, so it must not error and must not change state.
	proxy := &DarwinSystemProxy{serverAddr: M.ParseSocksaddrHostPort("127.0.0.1", 12334)}
	if err := proxy.disableOwnedServices(); err != nil {
		t.Skipf("networksetup unavailable: %v", err)
	}
	services, err := listNetworkServices()
	if err != nil {
		t.Skipf("networksetup unavailable: %v", err)
	}
	for _, service := range services {
		if state, err := readDarwinProxyState(service); err == nil {
			if state.pointsTo(proxy.serverAddr) {
				t.Fatalf("service %q still points at us after Disable", service)
			}
		}
	}
}
