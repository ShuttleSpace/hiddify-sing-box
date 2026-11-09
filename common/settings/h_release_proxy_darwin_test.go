//go:build darwin

package settings

import (
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// The tests below register proxies on ports nothing listens on, so the sweep a
// release triggers finds no entry of ours and writes nothing.
const hUnusedTestPort = 45999

func hResetActiveProxies() {
	activeProxiesMutex.Lock()
	defer activeProxiesMutex.Unlock()
	clear(activeProxies)
	lastProxyPortMutex.Lock()
	lastProxyPort = 0
	lastProxyPortMutex.Unlock()
}

func TestH_ReleaseSystemProxyIsANoOpWhenNothingIsActive(t *testing.T) {
	hResetActiveProxies()
	if err := ReleaseSystemProxy(); err != nil {
		t.Fatalf("releasing with nothing active must succeed, got %v", err)
	}
}

// A release has to reach an enabled proxy, and a Disable has to leave the registry
// clean, or a later release would sweep again for something already handed back.
func TestH_ReleaseSystemProxyDisablesWhatIsRegistered(t *testing.T) {
	hResetActiveProxies()
	proxy := &DarwinSystemProxy{
		serverAddr:   M.Socksaddr{Port: hUnusedTestPort},
		supportSOCKS: true,
	}
	proxy.register()
	if err := ReleaseSystemProxy(); err != nil {
		t.Fatalf("release: %v", err)
	}
	activeProxiesMutex.Lock()
	remaining := len(activeProxies)
	activeProxiesMutex.Unlock()
	if remaining != 0 {
		t.Fatalf("registry still holds %d entries after a release", remaining)
	}
}

func TestH_UnregisterDoesNotEvictAFreshOwner(t *testing.T) {
	hResetActiveProxies()
	first := &DarwinSystemProxy{serverAddr: M.Socksaddr{Port: hUnusedTestPort}}
	second := &DarwinSystemProxy{serverAddr: M.Socksaddr{Port: hUnusedTestPort}}
	first.register()
	second.register()

	first.unregister()

	activeProxiesMutex.Lock()
	owner := activeProxies[hUnusedTestPort]
	activeProxiesMutex.Unlock()
	if owner != second {
		t.Fatal("a stale Disable must not evict the proxy that took over the port")
	}
}

// releaseCommands is the decision core of the sweep: it must switch off only
// entries addressed at our listener, rewrite the host of our own stale residue,
// and leave another tool's proxy completely alone.
func TestH_ReleaseCommandsOnlyTargetsOurListener(t *testing.T) {
	service := "Wi-Fi"
	commands := func(state darwinProxyState) [][]string {
		return releaseCommands(service, int(hUnusedTestPort), &state)
	}

	t.Run("enabled entry on our port is switched off", func(t *testing.T) {
		got := commands(darwinProxyState{webEnabled: true, webServer: "127.0.0.1", webPort: hUnusedTestPort})
		want := [][]string{{"networksetup", "-setwebproxystate", service, "off"}}
		assertCommands(t, got, want)
	})

	t.Run("another tool's proxy is left alone", func(t *testing.T) {
		got := commands(darwinProxyState{webEnabled: true, webServer: "10.0.0.1", webPort: 8080})
		if len(got) != 0 {
			t.Fatalf("a proxy on another port must not be touched, got %v", got)
		}
	})

	t.Run("our stale ::1 residue has its host rewritten without enabling it", func(t *testing.T) {
		got := commands(darwinProxyState{webServer: "::1", webPort: hUnusedTestPort})
		want := [][]string{{"networksetup", "-setwebproxy", service, "127.0.0.1", "45999"}}
		assertCommands(t, got, want)
	})
}

func assertCommands(t *testing.T, got [][]string, want [][]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d commands, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if len(got[i]) != len(want[i]) {
			t.Fatalf("command %d: got %v, want %v", i, got[i], want[i])
		}
		for j := range want[i] {
			if got[i][j] != want[i][j] {
				t.Fatalf("command %d arg %d: got %q, want %q", i, j, got[i][j], want[i][j])
			}
		}
	}
}

// The registry is written from the inbound start path and read from the RPC path,
// so a release racing repeated registration has to stay consistent.
func TestH_ActiveProxiesSurvivesConcurrentRegisterAndRelease(t *testing.T) {
	hResetActiveProxies()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy := &DarwinSystemProxy{serverAddr: M.Socksaddr{Port: hUnusedTestPort - 1}}
			proxy.register()
			proxy.unregister()
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ReleaseSystemProxy()
		}()
	}
	wg.Wait()
	hResetActiveProxies()
}
