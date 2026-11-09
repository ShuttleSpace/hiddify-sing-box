//go:build darwin

package settings

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/shell"
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
		// Best-effort. Upstream's Disable resolves the interface by its display
		// name, which can fail when a service was renamed or the route moved to a
		// utun device; the port sweep below is what reliably hands the OS back.
		// Clear isEnabled even on failure so the interface-monitor callback does
		// not re-apply the proxy we are removing.
		_ = proxy.Disable()
		proxy.access.Lock()
		proxy.isEnabled = false
		proxy.access.Unlock()
		// Unregister here rather than relying on upstream's disableLocked: a //H
		// line inside that method is the first thing a rebase would drop, and the
		// release must leave the registry clean on its own.
		proxy.unregister()
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
		if err := releaseService(serviceName, int(port), state); err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}

type darwinProxyState struct {
	webEnabled    bool
	webServer     string
	webPort       int
	secureEnabled bool
	secureServer  string
	securePort    int
	socksEnabled  bool
	socksServer   string
	socksPort     int
	bypassDomains []string
}

// holdsOurListener reports whether any entry on this service is addressed to our
// listener. The port is what identifies us; the host only has to be a loopback
// address. Matching the exact host string instead would orphan every entry written
// by an older build, which recorded ::1 rather than 127.0.0.1, and that residue is
// precisely what kept System Settings showing a live proxy after we disconnected.
func (s *darwinProxyState) holdsOurListener(serverAddr M.Socksaddr) bool {
	port := int(serverAddr.Port)
	return entryIsOurListener(s.webServer, s.webPort, port) ||
		entryIsOurListener(s.secureServer, s.securePort, port) ||
		entryIsOurListener(s.socksServer, s.socksPort, port)
}

func entryIsOurListener(server string, port int, ourPort int) bool {
	return port == ourPort && isLoopbackHost(server)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// releaseService runs the networksetup commands releaseCommands builds.
func releaseService(serviceName string, port int, state *darwinProxyState) error {
	var errs []error
	for _, command := range releaseCommands(serviceName, port, state) {
		if err := shell.Exec(command[0], command[1:]...).Attach().Run(); err != nil {
			errs = append(errs, E.Cause(err, strings.Join(command, " ")))
		}
	}
	return E.Errors(errs...)
}

// releaseCommands builds the networksetup invocations release runs, so the
// decisions it makes can be asserted without touching the live network settings.
//
// Web, secure and SOCKS are handled one entry at a time rather than as a service,
// because a service can carry both our entry and another tool's: the sweeper
// reaches services that merely hold residue, and switching the whole service off
// there would take the other tool's proxy down with it.
func releaseCommands(serviceName string, port int, state *darwinProxyState) [][]string {
	host := "127.0.0.1"
	portText := strconv.Itoa(port)
	ourPort := port
	var commands [][]string

	releaseEntry := func(setFlag string, server string, entryPort int, enabled bool) {
		if !entryIsOurListener(server, entryPort, ourPort) {
			return
		}
		if server != host {
			commands = append(commands, []string{"networksetup", setFlag, serviceName, host, portText})
		}
		if enabled {
			// Every host flag has a matching state flag: -setwebproxy pairs with
			// -setwebproxystate, -setsocksfirewallproxy with -setsocksfirewallproxystate.
			commands = append(commands, []string{"networksetup", setFlag + "state", serviceName, "off"})
		}
	}
	releaseEntry("-setwebproxy", state.webServer, state.webPort, state.webEnabled)
	releaseEntry("-setsecurewebproxy", state.secureServer, state.securePort, state.secureEnabled)
	if state.socksEnabled || state.socksServer != "" {
		releaseEntry("-setsocksfirewallproxy", state.socksServer, state.socksPort, state.socksEnabled)
	}
	return commands
}

func listNetworkServices() ([]string, error) {
	output, err := shell.Exec("networksetup", "-listallnetworkservices").ReadOutput()
	if err != nil {
		return nil, err
	}
	var services []string
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		// networksetup prints a legend above the list and marks disabled services
		// with a leading asterisk.
		if trimmed == "" || strings.HasPrefix(trimmed, "An asterisk") {
			continue
		}
		services = append(services, strings.TrimSpace(strings.TrimPrefix(trimmed, "* ")))
	}
	return services, nil
}

func readDarwinProxyState(serviceName string) (*darwinProxyState, error) {
	webOutput, err := shell.Exec("networksetup", "-getwebproxy", serviceName).ReadOutput()
	if err != nil {
		return nil, err
	}
	webEnabled, webServer, webPort := parseProxyOutput(webOutput)

	secureOutput, err := shell.Exec("networksetup", "-getsecurewebproxy", serviceName).ReadOutput()
	if err != nil {
		return nil, err
	}
	secureEnabled, secureServer, securePort := parseProxyOutput(secureOutput)

	var socksEnabled bool
	var socksServer string
	var socksPort int
	if sockOutput, sockErr := shell.Exec("networksetup", "-getsocksfirewallproxy", serviceName).ReadOutput(); sockErr == nil {
		socksEnabled, socksServer, socksPort = parseProxyOutput(sockOutput)
	}

	bypassOutput, err := shell.Exec("networksetup", "-getproxybypassdomains", serviceName).ReadOutput()
	if err != nil {
		return nil, err
	}
	bypassDomains := strings.Fields(strings.ReplaceAll(bypassOutput, "\r\n", "\n"))
	if bypassDomains == nil {
		bypassDomains = []string{}
	}

	return &darwinProxyState{
		webEnabled:    webEnabled,
		webServer:     webServer,
		webPort:       webPort,
		secureEnabled: secureEnabled,
		secureServer:  secureServer,
		securePort:    securePort,
		socksEnabled:  socksEnabled,
		socksServer:   socksServer,
		socksPort:     socksPort,
		bypassDomains: bypassDomains,
	}, nil
}

func parseProxyOutput(output string) (bool, string, int) {
	enabled := false
	server := ""
	port := 0
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Enabled:") {
			enabled = strings.TrimSpace(strings.TrimPrefix(trimmed, "Enabled:")) == "Yes"
		} else if strings.HasPrefix(trimmed, "Server:") {
			server = strings.TrimSpace(strings.TrimPrefix(trimmed, "Server:"))
		} else if strings.HasPrefix(trimmed, "Port:") {
			port, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(trimmed, "Port:")))
		}
	}
	return enabled, server, port
}
