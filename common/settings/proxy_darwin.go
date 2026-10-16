package settings

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/shell"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
)

type DarwinSystemProxy struct {
	monitor       tun.DefaultInterfaceMonitor
	interfaceName string
	// serviceName is the name networksetup is addressed by. It is not the device
	// name and not the hardware port name: it is whatever the user calls the
	// network service in System Settings > Network, and the two can be renamed
	// independently.
	serviceName  string
	element      *list.Element[tun.DefaultInterfaceUpdateCallback]
	serverAddr   M.Socksaddr
	supportSOCKS bool
	// access guards the ownership state (isEnabled, previous, serviceName) from
	// concurrent mutation. Enable, routeUpdate and a release arriving over the RPC
	// all write it, and from three different goroutines.
	access    sync.Mutex
	isEnabled bool
	previous  *darwinProxyState
	watchdog  *exec.Cmd
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

func NewSystemProxy(ctx context.Context, serverAddr M.Socksaddr, supportSOCKS bool) (*DarwinSystemProxy, error) {
	interfaceMonitor := service.FromContext[adapter.NetworkManager](ctx).InterfaceMonitor()
	if interfaceMonitor == nil {
		return nil, E.New("missing interface monitor")
	}
	proxy := &DarwinSystemProxy{
		monitor:      interfaceMonitor,
		serverAddr:   serverAddr,
		supportSOCKS: supportSOCKS,
	}
	proxy.element = interfaceMonitor.RegisterCallback(proxy.routeUpdate)
	return proxy, nil
}

func (p *DarwinSystemProxy) IsEnabled() bool {
	p.access.Lock()
	defer p.access.Unlock()
	return p.isEnabled
}

func (p *DarwinSystemProxy) Enable() error {
	return p.update0()
}

// Disable releases the proxy entries we installed. It no longer resolves the
// current default interface: that lookup stays off the hardware-port list once the
// route moves to a utun/bridge device, and returning early there is what left the
// switches enabled with nothing able to turn them off.
func (p *DarwinSystemProxy) Disable() error {
	p.access.Lock()
	defer p.access.Unlock()
	return p.disableLocked()
}

// disableLocked is Disable with the state lock already held. update0 disables and
// re-applies in one go, and it runs on the interface monitor's goroutine, so it
// cannot go back through Disable.
func (p *DarwinSystemProxy) disableLocked() error {
	p.stopWatchdog()
	// Drop out of the registry first. A release racing this sweep would otherwise
	// call back into a Disable that is already running.
	p.unregister()
	var errs []error
	if err := p.disableOwnedServices(); err != nil {
		errs = append(errs, err)
	}
	p.isEnabled = false
	p.previous = nil
	return E.Errors(errs...)
}

// disableOwnedServices releases every service that still holds one of our proxy
// entries. A service is only touched while it still points at us, so a proxy
// belonging to another tool is never cleared.
func (p *DarwinSystemProxy) disableOwnedServices() error {
	services, err := listNetworkServices()
	if err != nil {
		return err
	}
	var errs []error
	for _, serviceName := range services {
		state, err := readDarwinProxyState(serviceName)
		if err != nil {
			// An unreadable service cannot be shown to be ours, so leave it alone.
			continue
		}
		if !state.holdsOurListener(p.serverAddr) {
			continue
		}
		// Only the service we actually wrote to carries a captured previous state.
		if p.previous != nil && p.serviceName == serviceName && !p.previous.pointsTo(p.serverAddr) {
			errs = append(errs, p.restore(serviceName, p.previous))
			continue
		}
		errs = append(errs, p.release(serviceName, state))
	}
	return E.Errors(errs...)
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

// routesThroughUs reports whether a switched-on entry on this service is addressed
// to our listener. That is the only state in which the service still hands traffic
// to a port we are about to close, so it is what "released" has to mean.
func (s *darwinProxyState) routesThroughUs(serverAddr M.Socksaddr) bool {
	port := int(serverAddr.Port)
	return (s.webEnabled && entryIsOurListener(s.webServer, s.webPort, port)) ||
		(s.secureEnabled && entryIsOurListener(s.secureServer, s.securePort, port)) ||
		(s.socksEnabled && entryIsOurListener(s.socksServer, s.socksPort, port))
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// serviceStillOurs reports whether a service currently routes at our listener.
func (p *DarwinSystemProxy) serviceStillOurs(serviceName string) bool {
	state, err := readDarwinProxyState(serviceName)
	if err != nil {
		return false
	}
	return state.pointsTo(p.serverAddr)
}

// pointsTo is the strict form: the entry is enabled and addressed exactly the way
// we address it. It answers "did our own write land and is it still on", which is
// what lets update0 skip re-applying. Use holdsOurListener to decide what to clean.
func (s *darwinProxyState) pointsTo(serverAddr M.Socksaddr) bool {
	server := serverAddr.AddrString()
	port := int(serverAddr.Port)
	return (s.webEnabled && s.webServer == server && s.webPort == port) ||
		(s.secureEnabled && s.secureServer == server && s.securePort == port) ||
		(s.socksEnabled && s.socksServer == server && s.socksPort == port)
}

func (p *DarwinSystemProxy) routeUpdate(defaultInterface *control.Interface, flags int) {
	if defaultInterface == nil {
		return
	}
	p.access.Lock()
	defer p.access.Unlock()
	if !p.isEnabled {
		return
	}
	_ = p.updateLocked()
}

func (p *DarwinSystemProxy) update0() error {
	p.access.Lock()
	defer p.access.Unlock()
	return p.updateLocked()
}

func (p *DarwinSystemProxy) updateLocked() error {
	newInterface := p.monitor.DefaultInterface()
	if newInterface == nil {
		// DefaultInterface is a bare atomic load: nil until the route table has
		// been walked, and again whenever no interface is up. There is no service
		// to apply the proxy to, and dereferencing it here would take the process
		// down from inside Listener.Start.
		return E.New("no default interface to set the system proxy on")
	}
	if p.isEnabled && p.interfaceName == newInterface.Name && p.serviceName != "" {
		if p.serviceStillOurs(p.serviceName) {
			return nil
		}
	}
	if p.interfaceName != "" {
		_ = p.disableLocked()
	}
	// Resolve the service name before committing the interface. A device the
	// hardware-port list does not know (utun, bridge, ...) has to leave
	// interfaceName untouched: committing it is what poisoned every later Disable
	// and made the proxy switches stay on for the rest of the session.
	serviceName, err := serviceNameForDevice(newInterface.Name)
	if err != nil {
		return err
	}
	if p.isEnabled && p.serviceName != "" && p.serviceName != serviceName {
		if err = p.disableAll(p.serviceName); err != nil {
			return err
		}
	}
	p.interfaceName = newInterface.Name
	p.serviceName = serviceName
	if p.previous == nil {
		p.previous, err = readDarwinProxyState(serviceName)
		if err != nil {
			return err
		}
	}
	// Claim ownership before the first write. A half-applied proxy is still ours to
	// clean up, so isEnabled must not depend on every command succeeding.
	p.isEnabled = true
	p.register()
	if p.supportSOCKS {
		err = shell.Exec("networksetup", "-setsocksfirewallproxy", serviceName, p.serverAddr.AddrString(), strconv.Itoa(int(p.serverAddr.Port))).Attach().Run()
	}
	if err != nil {
		return err
	}
	err = shell.Exec("networksetup", "-setwebproxy", serviceName, p.serverAddr.AddrString(), strconv.Itoa(int(p.serverAddr.Port))).Attach().Run()
	if err != nil {
		return err
	}
	err = shell.Exec("networksetup", "-setsecurewebproxy", serviceName, p.serverAddr.AddrString(), strconv.Itoa(int(p.serverAddr.Port))).Attach().Run()
	if err != nil {
		return err
	}
	err = shell.Exec(
		"networksetup",
		"-setproxybypassdomains",
		serviceName,
		"localhost",
		"127.0.0.1",
		"::1",
		"*.local",
	).Attach().Run()
	if err != nil {
		return err
	}
	p.startWatchdog(p.serviceName, p.previous)
	return nil
}

func (p *DarwinSystemProxy) startWatchdog(serviceName string, state *darwinProxyState) {
	p.stopWatchdog()
	script := p.restoreScript(serviceName, state)
	cmd := exec.Command(
		"/bin/sh",
		"-c",
		fmt.Sprintf("while kill -0 %d 2>/dev/null; do sleep 1; done; %s", os.Getpid(), script),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return
	}
	p.watchdog = cmd
	go func() {
		_ = cmd.Wait()
	}()
}

func (p *DarwinSystemProxy) stopWatchdog() {
	if p.watchdog == nil || p.watchdog.Process == nil {
		return
	}
	_ = p.watchdog.Process.Kill()
	p.watchdog = nil
}

func (p *DarwinSystemProxy) restoreScript(serviceName string, state *darwinProxyState) string {
	var commands []string

	if state.socksEnabled {
		commands = append(commands, shellCommand(
			"networksetup", "-setsocksfirewallproxy", serviceName, state.socksServer, strconv.Itoa(state.socksPort),
		))
		commands = append(commands, shellCommand("networksetup", "-setsocksfirewallproxystate", serviceName, "on"))
	} else if p.supportSOCKS {
		commands = append(commands, shellCommand("networksetup", "-setsocksfirewallproxystate", serviceName, "off"))
	}

	if state.webEnabled {
		commands = append(commands, shellCommand(
			"networksetup", "-setwebproxy", serviceName, state.webServer, strconv.Itoa(state.webPort),
		))
		commands = append(commands, shellCommand("networksetup", "-setwebproxystate", serviceName, "on"))
	} else {
		commands = append(commands, shellCommand("networksetup", "-setwebproxystate", serviceName, "off"))
	}

	if state.secureEnabled {
		commands = append(commands, shellCommand(
			"networksetup", "-setsecurewebproxy", serviceName, state.secureServer, strconv.Itoa(state.securePort),
		))
		commands = append(commands, shellCommand("networksetup", "-setsecurewebproxystate", serviceName, "on"))
	} else {
		commands = append(commands, shellCommand("networksetup", "-setsecurewebproxystate", serviceName, "off"))
	}

	bypassArgs := []string{"networksetup", "-setproxybypassdomains", serviceName}
	bypassArgs = append(bypassArgs, state.bypassDomains...)
	commands = append(commands, shellCommand(bypassArgs[0], bypassArgs[1:]...))

	return strings.Join(commands, " ; ")
}

func shellCommand(name string, args ...string) string {
	parts := []string{name}
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (p *DarwinSystemProxy) disableAll(serviceName string) error {
	if p.supportSOCKS {
		if err := shell.Exec("networksetup", "-setsocksfirewallproxystate", serviceName, "off").Attach().Run(); err != nil {
			return err
		}
	}
	if err := shell.Exec("networksetup", "-setwebproxystate", serviceName, "off").Attach().Run(); err != nil {
		return err
	}
	return shell.Exec("networksetup", "-setsecurewebproxystate", serviceName, "off").Attach().Run()
}

// release hands the service back to the user: every switch that can address our
// listener goes off, and each entry we own has its recorded host rewritten to the
// address we write today.
//
// The rewrite is not cosmetic. networksetup keeps the host after a switch is
// turned off, so a leftover ::1 entry stays visible in System Settings > Network
// and reads as a proxy that is still configured. Only entries still on our port are
// rewritten, so another tool's settings survive untouched.
func (p *DarwinSystemProxy) release(serviceName string, state *darwinProxyState) error {
	var errs []error
	for _, command := range p.releaseCommands(serviceName, state) {
		if err := shell.Exec(command[0], command[1:]...).Attach().Run(); err != nil {
			errs = append(errs, E.Cause(err, strings.Join(command, " ")))
		}
	}
	return E.Errors(errs...)
}

// releaseCommands builds the networksetup invocations release runs, so the
// decisions it makes can be asserted without touching the live network settings.
func (p *DarwinSystemProxy) releaseCommands(serviceName string, state *darwinProxyState) [][]string {
	host := p.serverAddr.AddrString()
	port := strconv.Itoa(int(p.serverAddr.Port))
	ourPort := int(p.serverAddr.Port)
	var commands [][]string

	// Web, secure and SOCKS are handled one entry at a time rather than as a
	// service, because a service can carry both our entry and another tool's: the
	// sweeper reaches services that merely hold residue, and switching the whole
	// service off there would take the other tool's proxy down with it.
	releaseEntry := func(setFlag string, server string, entryPort int, enabled bool) {
		if !entryIsOurListener(server, entryPort, ourPort) {
			return
		}
		if server != host {
			commands = append(commands, []string{"networksetup", setFlag, serviceName, host, port})
		}
		if enabled {
			// Every host flag has a matching state flag: -setwebproxy pairs with
			// -setwebproxystate, -setsocksfirewallproxy with -setsocksfirewallproxystate.
			commands = append(commands, []string{"networksetup", setFlag + "state", serviceName, "off"})
		}
	}
	releaseEntry("-setwebproxy", state.webServer, state.webPort, state.webEnabled)
	releaseEntry("-setsecurewebproxy", state.secureServer, state.securePort, state.secureEnabled)
	if p.supportSOCKS {
		releaseEntry("-setsocksfirewallproxy", state.socksServer, state.socksPort, state.socksEnabled)
	}
	return commands
}

func (p *DarwinSystemProxy) restore(serviceName string, state *darwinProxyState) error {
	if state.socksEnabled {
		if err := shell.Exec(
			"networksetup",
			"-setsocksfirewallproxy",
			serviceName,
			state.socksServer,
			strconv.Itoa(state.socksPort),
		).Attach().Run(); err != nil {
			return err
		}
		if err := shell.Exec("networksetup", "-setsocksfirewallproxystate", serviceName, "on").Attach().Run(); err != nil {
			return err
		}
	} else if p.supportSOCKS {
		if err := shell.Exec("networksetup", "-setsocksfirewallproxystate", serviceName, "off").Attach().Run(); err != nil {
			return err
		}
	}

	if state.webEnabled {
		if err := shell.Exec("networksetup", "-setwebproxy", serviceName, state.webServer, strconv.Itoa(state.webPort)).Attach().Run(); err != nil {
			return err
		}
		if err := shell.Exec("networksetup", "-setwebproxystate", serviceName, "on").Attach().Run(); err != nil {
			return err
		}
	} else if err := shell.Exec("networksetup", "-setwebproxystate", serviceName, "off").Attach().Run(); err != nil {
		return err
	}

	if state.secureEnabled {
		if err := shell.Exec("networksetup", "-setsecurewebproxy", serviceName, state.secureServer, strconv.Itoa(state.securePort)).Attach().Run(); err != nil {
			return err
		}
		if err := shell.Exec("networksetup", "-setsecurewebproxystate", serviceName, "on").Attach().Run(); err != nil {
			return err
		}
	} else if err := shell.Exec("networksetup", "-setsecurewebproxystate", serviceName, "off").Attach().Run(); err != nil {
		return err
	}

	args := append([]string{"-setproxybypassdomains", serviceName}, state.bypassDomains...)
	return shell.Exec("networksetup", args...).Attach().Run()
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

func getInterfaceDisplayName(name string) (string, error) {
	content, err := shell.Exec("networksetup", "-listallhardwareports").ReadOutput()
	if err != nil {
		return "", err
	}
	for _, deviceSpan := range strings.Split(string(content), "Ethernet Address") {
		if strings.Contains(deviceSpan, "Device: "+name) {
			substr := "Hardware Port: "
			deviceSpan = deviceSpan[strings.Index(deviceSpan, substr)+len(substr):]
			deviceSpan = deviceSpan[:strings.Index(deviceSpan, "\n")]
			return deviceSpan, nil
		}
	}
	return "", E.New(name, " not found in networksetup -listallhardwareports")
}

// serviceNameForDevice resolves the name networksetup should be addressed by for a
// network device.
//
// The hardware port name is not that name. A hardware port is what the hardware
// calls itself; a network service is a user-facing name, editable on its own in
// System Settings > Network. They coincide on a default install and diverge the
// moment anyone renames a service, and networksetup rejects a hardware port name
// it does not also recognise as a service ("The parameters were not valid"), so
// proxying silently stops working for exactly the people who named their services.
func serviceNameForDevice(device string) (string, error) {
	order, err := shell.Exec("networksetup", "-listnetworkserviceorder").ReadOutput()
	if err != nil {
		return "", err
	}
	if serviceName := parseServiceNameForDevice(string(order), device); serviceName != "" {
		return serviceName, nil
	}
	// Devices that are not services of their own (utun, bridge pairs, anything
	// Tailscale creates) have no service to configure, so the hardware port name is
	// all that is left to try.
	return getInterfaceDisplayName(device)
}

// parseServiceNameForDevice reads the "(N) Name" / "(Hardware Port: P, Device: D)"
// pairs that -listnetworkserviceorder prints and returns the name belonging to
// device, or "" when the device is not listed.
func parseServiceNameForDevice(order string, device string) string {
	pendingName := ""
	for _, line := range strings.Split(order, "\n") {
		line = strings.TrimSpace(line)
		if name, ok := parseServiceOrderName(line); ok {
			pendingName = name
			continue
		}
		if entryDevice, ok := parseServiceOrderDetail(line); ok {
			if entryDevice == device {
				return pendingName
			}
			// The name has been paired with its detail line and belongs to no
			// device we can match, so it must not leak into the next entry.
			pendingName = ""
		}
	}
	return ""
}

// parseServiceOrderName matches the index line, "(1) Wi-Fi". The asterisk the
// legend line and the detail line both start with are what keep them out: neither
// has digits between the parentheses.
func parseServiceOrderName(line string) (string, bool) {
	if !strings.HasPrefix(line, "(") {
		return "", false
	}
	end := strings.Index(line, ")")
	if end < 0 {
		return "", false
	}
	index := line[1:end]
	if strings.HasPrefix(index, "*") {
		index = index[1:]
	}
	if index == "" || strings.Trim(index, "0123456789") != "" {
		return "", false
	}
	// A disabled service is listed as "(2) * My VPN".
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line[end+1:]), "*")), true
}

// parseServiceOrderDetail matches the detail line, "(Hardware Port: Wi-Fi, Device: en0)",
// and returns the device. A service with no device of its own reports an empty one
// and is never returned: an empty query would otherwise match it.
func parseServiceOrderDetail(line string) (string, bool) {
	if !strings.HasSuffix(line, ")") {
		return "", false
	}
	rest, ok := strings.CutPrefix(line, "(Hardware Port: ")
	if !ok {
		return "", false
	}
	_, after, ok := strings.Cut(rest, ", Device:")
	if !ok {
		return "", false
	}
	device := strings.TrimSpace(strings.TrimSuffix(after, ")"))
	if device == "" {
		return "", false
	}
	return device, true
}
