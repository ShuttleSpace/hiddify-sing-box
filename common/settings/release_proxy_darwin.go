package settings

import (
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

// The system proxy is owned by the inbound that created it and lives as long as
// that inbound does, so nothing outside can reach it to hand the OS back when the
// reason for holding it goes away. Switching the service mode away from the system
// proxy is exactly that moment: the tunnel keeps running, but the OS setting has to
// follow the mode the user just picked.
//
// Rather than reach into the box, an enabled proxy registers itself here. There is
// at most one per mixed port, and the entry is removed the moment it is disabled,
// so what a release finds is always what the OS is actually pointing at.
var (
	activeProxiesMutex sync.Mutex
	activeProxies      = map[uint16]*DarwinSystemProxy{}
)

func (p *DarwinSystemProxy) register() {
	activeProxiesMutex.Lock()
	defer activeProxiesMutex.Unlock()
	activeProxies[p.serverAddr.Port] = p
}

func (p *DarwinSystemProxy) unregister() {
	activeProxiesMutex.Lock()
	defer activeProxiesMutex.Unlock()
	// Identity, not just the port: a Disable racing a newer Enable on the same
	// port must not evict the instance that took over.
	if activeProxies[p.serverAddr.Port] == p {
		delete(activeProxies, p.serverAddr.Port)
	}
}

func releaseSystemProxy() error {
	activeProxiesMutex.Lock()
	owned := make([]*DarwinSystemProxy, 0, len(activeProxies))
	for _, proxy := range activeProxies {
		owned = append(owned, proxy)
	}
	activeProxiesMutex.Unlock()

	// Disable unregisters, so the set is snapshotted rather than walked in place.
	var errs []error
	for _, proxy := range owned {
		if err := proxy.Disable(); err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}
