package settings

import (
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// The tests below register proxies on ports nothing listens on, so the sweep a
// release triggers finds no entry of ours and writes nothing.
const unusedTestPort = 45999

func resetActiveProxies() {
	activeProxiesMutex.Lock()
	defer activeProxiesMutex.Unlock()
	clear(activeProxies)
}

func TestReleaseSystemProxyIsANoOpWhenNothingIsActive(t *testing.T) {
	resetActiveProxies()
	if err := ReleaseSystemProxy(); err != nil {
		t.Fatalf("releasing with nothing active must succeed, got %v", err)
	}
}

// A release has to reach an enabled proxy, and a Disable has to leave the registry
// clean, or a later release would sweep again for something already handed back.
func TestReleaseSystemProxyDisablesWhatIsRegistered(t *testing.T) {
	resetActiveProxies()
	proxy := &DarwinSystemProxy{
		serverAddr:   M.ParseSocksaddrHostPort("127.0.0.1", unusedTestPort),
		supportSOCKS: true,
	}
	proxy.register()
	// Registered but not enabled: Disable must still run the sweep and drop it.
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

func TestUnregisterDoesNotEvictAFreshOwner(t *testing.T) {
	resetActiveProxies()
	first := &DarwinSystemProxy{serverAddr: M.ParseSocksaddrHostPort("127.0.0.1", unusedTestPort)}
	second := &DarwinSystemProxy{serverAddr: M.ParseSocksaddrHostPort("127.0.0.1", unusedTestPort)}
	first.register()
	second.register()

	first.unregister()

	activeProxiesMutex.Lock()
	owner := activeProxies[unusedTestPort]
	activeProxiesMutex.Unlock()
	if owner != second {
		t.Fatal("a stale Disable must not evict the proxy that took over the port")
	}
}

// The registry is written from the inbound start path and read from the RPC path,
// so a release racing repeated registration has to stay consistent.
func TestActiveProxiesSurvivesConcurrentRegisterAndRelease(t *testing.T) {
	resetActiveProxies()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy := &DarwinSystemProxy{serverAddr: M.ParseSocksaddrHostPort("127.0.0.1", unusedTestPort-1)}
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
	resetActiveProxies()
}
