package settings

import (
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
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

// The ports this build sets a system proxy on. Recorded at the moment of the write,
// because the inbound that did it is gone by the time anyone asks for it back.
//
// A release has to work across process boundaries: turning the service mode to
// VPN-only in System Settings, or closing the app, leaves no listener running and
// therefore nothing registered, while the switches stay on. The registry cannot
// answer for that, so the last port is kept next to it.
var (
	lastProxyPortMutex sync.Mutex
	lastProxyPort      uint16
)

func (p *DarwinSystemProxy) register() {
	activeProxiesMutex.Lock()
	defer activeProxiesMutex.Unlock()
	activeProxies[p.serverAddr.Port] = p
	lastProxyPortMutex.Lock()
	lastProxyPort = p.serverAddr.Port
	lastProxyPortMutex.Unlock()
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
	port := lastProxyPort
	activeProxiesMutex.Unlock()

	// Disable unregisters, so the set is snapshotted rather than walked in place.
	var errs []error
	for _, proxy := range owned {
		if err := proxy.Disable(); err != nil {
			errs = append(errs, err)
		}
	}
	// Nothing is registered when the listener that owned the proxy is already
	// gone, which is exactly the case a release is asked about: the app or the
	// tunnel was closed, or System Settings moved the mode on without us. Sweep
	// the port we last wrote so the switches still go down.
	if err := releasePort(port); err != nil {
		errs = append(errs, err)
	}
	return E.Errors(errs...)
}

// releasePort switches off every entry addressed to this port and points it back at
// the loopback address. It is the fallback for a proxy whose inbound no longer
// exists, so there is no previous state to restore: what is on screen is our own
// residue, and leaving it enabled is the bug being fixed here.
func releasePort(port uint16) error {
	if port == 0 {
		return nil
	}
	services, err := listNetworkServices()
	if err != nil {
		return err
	}
	var errs []error
	for _, serviceName := range services {
		state, err := readDarwinProxyState(serviceName)
		if err != nil {
			continue
		}
		if !state.holdsOurListener(M.Socksaddr{Port: port}) {
			continue
		}
		if err := releaseService(serviceName, int(port), true, state); err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}
