package settings

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
	displayName   string
	element       *list.Element[tun.DefaultInterfaceUpdateCallback]
	serverAddr    M.Socksaddr
	supportSOCKS  bool
	isEnabled     bool
	previous      *darwinProxyState
	watchdog      *exec.Cmd
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
	p.stopWatchdog()
	var errs []error
	if err := p.disableOwnedServices(); err != nil {
		errs = append(errs, err)
	}
	p.isEnabled = false
	p.previous = nil
	return E.Errors(errs...)
}

// disableOwnedServices releases every service that still routes at our listener.
// A service is only touched while it still points at us, so a proxy belonging to
// another tool is never cleared.
func (p *DarwinSystemProxy) disableOwnedServices() error {
	services, err := listNetworkServices()
	if err != nil {
		return err
	}
	var errs []error
	for _, serviceName := range services {
		if !p.serviceStillOurs(serviceName) {
			continue
		}
		if p.previous != nil && p.displayName == serviceName && !p.previous.pointsTo(p.serverAddr) {
			errs = append(errs, p.restore(serviceName, p.previous))
		} else {
			errs = append(errs, p.disableAll(serviceName))
		}
	}
	return E.Errors(errs...)
}

// serviceStillOurs reports whether a service currently routes at our listener.
func (p *DarwinSystemProxy) serviceStillOurs(serviceName string) bool {
	state, err := readDarwinProxyState(serviceName)
	if err != nil {
		return false
	}
	return state.pointsTo(p.serverAddr)
}

func (s *darwinProxyState) pointsTo(serverAddr M.Socksaddr) bool {
	server := serverAddr.AddrString()
	port := int(serverAddr.Port)
	return (s.webEnabled && s.webServer == server && s.webPort == port) ||
		(s.secureEnabled && s.secureServer == server && s.securePort == port) ||
		(s.socksEnabled && s.socksServer == server && s.socksPort == port)
}

func (p *DarwinSystemProxy) routeUpdate(defaultInterface *control.Interface, flags int) {
	if !p.isEnabled || defaultInterface == nil {
		return
	}
	_ = p.update0()
}

func (p *DarwinSystemProxy) update0() error {
	newInterface := p.monitor.DefaultInterface()
	if p.isEnabled && p.interfaceName == newInterface.Name && p.displayName != "" {
		if p.serviceStillOurs(p.displayName) {
			return nil
		}
	}
	if p.interfaceName != "" {
		_ = p.Disable()
	}
	// Resolve the display name before committing the interface. A device the
	// hardware-port list does not know (utun, bridge, ...) has to leave
	// interfaceName untouched: committing it is what poisoned every later Disable
	// and made the proxy switches stay on for the rest of the session.
	interfaceDisplayName, err := getInterfaceDisplayName(newInterface.Name)
	if err != nil {
		return err
	}
	if p.isEnabled && p.displayName != "" && p.displayName != interfaceDisplayName {
		if err = p.disableAll(p.displayName); err != nil {
			return err
		}
	}
	p.interfaceName = newInterface.Name
	p.displayName = interfaceDisplayName
	if p.previous == nil {
		p.previous, err = readDarwinProxyState(interfaceDisplayName)
		if err != nil {
			return err
		}
	}
	// Claim ownership before the first write. A half-applied proxy is still ours to
	// clean up, so isEnabled must not depend on every command succeeding.
	p.isEnabled = true
	if p.supportSOCKS {
		err = shell.Exec("networksetup", "-setsocksfirewallproxy", interfaceDisplayName, p.serverAddr.AddrString(), strconv.Itoa(int(p.serverAddr.Port))).Attach().Run()
	}
	if err != nil {
		return err
	}
	err = shell.Exec("networksetup", "-setwebproxy", interfaceDisplayName, p.serverAddr.AddrString(), strconv.Itoa(int(p.serverAddr.Port))).Attach().Run()
	if err != nil {
		return err
	}
	err = shell.Exec("networksetup", "-setsecurewebproxy", interfaceDisplayName, p.serverAddr.AddrString(), strconv.Itoa(int(p.serverAddr.Port))).Attach().Run()
	if err != nil {
		return err
	}
	err = shell.Exec(
		"networksetup",
		"-setproxybypassdomains",
		interfaceDisplayName,
		"localhost",
		"127.0.0.1",
		"::1",
		"*.local",
	).Attach().Run()
	if err != nil {
		return err
	}
	p.startWatchdog(p.displayName, p.previous)
	return nil
}

func (p *DarwinSystemProxy) startWatchdog(interfaceDisplayName string, state *darwinProxyState) {
	p.stopWatchdog()
	script := p.restoreScript(interfaceDisplayName, state)
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

func (p *DarwinSystemProxy) restoreScript(interfaceDisplayName string, state *darwinProxyState) string {
	var commands []string

	if state.socksEnabled {
		commands = append(commands, shellCommand(
			"networksetup", "-setsocksfirewallproxy", interfaceDisplayName, state.socksServer, strconv.Itoa(state.socksPort),
		))
		commands = append(commands, shellCommand("networksetup", "-setsocksfirewallproxystate", interfaceDisplayName, "on"))
	} else if p.supportSOCKS {
		commands = append(commands, shellCommand("networksetup", "-setsocksfirewallproxystate", interfaceDisplayName, "off"))
	}

	if state.webEnabled {
		commands = append(commands, shellCommand(
			"networksetup", "-setwebproxy", interfaceDisplayName, state.webServer, strconv.Itoa(state.webPort),
		))
		commands = append(commands, shellCommand("networksetup", "-setwebproxystate", interfaceDisplayName, "on"))
	} else {
		commands = append(commands, shellCommand("networksetup", "-setwebproxystate", interfaceDisplayName, "off"))
	}

	if state.secureEnabled {
		commands = append(commands, shellCommand(
			"networksetup", "-setsecurewebproxy", interfaceDisplayName, state.secureServer, strconv.Itoa(state.securePort),
		))
		commands = append(commands, shellCommand("networksetup", "-setsecurewebproxystate", interfaceDisplayName, "on"))
	} else {
		commands = append(commands, shellCommand("networksetup", "-setsecurewebproxystate", interfaceDisplayName, "off"))
	}

	bypassArgs := []string{"networksetup", "-setproxybypassdomains", interfaceDisplayName}
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

func (p *DarwinSystemProxy) disableAll(interfaceDisplayName string) error {
	if p.supportSOCKS {
		if err := shell.Exec("networksetup", "-setsocksfirewallproxystate", interfaceDisplayName, "off").Attach().Run(); err != nil {
			return err
		}
	}
	if err := shell.Exec("networksetup", "-setwebproxystate", interfaceDisplayName, "off").Attach().Run(); err != nil {
		return err
	}
	return shell.Exec("networksetup", "-setsecurewebproxystate", interfaceDisplayName, "off").Attach().Run()
}

func (p *DarwinSystemProxy) restore(interfaceDisplayName string, state *darwinProxyState) error {
	if state.socksEnabled {
		if err := shell.Exec(
			"networksetup",
			"-setsocksfirewallproxy",
			interfaceDisplayName,
			state.socksServer,
			strconv.Itoa(state.socksPort),
		).Attach().Run(); err != nil {
			return err
		}
		if err := shell.Exec("networksetup", "-setsocksfirewallproxystate", interfaceDisplayName, "on").Attach().Run(); err != nil {
			return err
		}
	} else if p.supportSOCKS {
		if err := shell.Exec("networksetup", "-setsocksfirewallproxystate", interfaceDisplayName, "off").Attach().Run(); err != nil {
			return err
		}
	}

	if state.webEnabled {
		if err := shell.Exec("networksetup", "-setwebproxy", interfaceDisplayName, state.webServer, strconv.Itoa(state.webPort)).Attach().Run(); err != nil {
			return err
		}
		if err := shell.Exec("networksetup", "-setwebproxystate", interfaceDisplayName, "on").Attach().Run(); err != nil {
			return err
		}
	} else if err := shell.Exec("networksetup", "-setwebproxystate", interfaceDisplayName, "off").Attach().Run(); err != nil {
		return err
	}

	if state.secureEnabled {
		if err := shell.Exec("networksetup", "-setsecurewebproxy", interfaceDisplayName, state.secureServer, strconv.Itoa(state.securePort)).Attach().Run(); err != nil {
			return err
		}
		if err := shell.Exec("networksetup", "-setsecurewebproxystate", interfaceDisplayName, "on").Attach().Run(); err != nil {
			return err
		}
	} else if err := shell.Exec("networksetup", "-setsecurewebproxystate", interfaceDisplayName, "off").Attach().Run(); err != nil {
		return err
	}

	args := append([]string{"-setproxybypassdomains", interfaceDisplayName}, state.bypassDomains...)
	return shell.Exec("networksetup", args...).Attach().Run()
}

func readDarwinProxyState(interfaceDisplayName string) (*darwinProxyState, error) {
	webOutput, err := shell.Exec("networksetup", "-getwebproxy", interfaceDisplayName).ReadOutput()
	if err != nil {
		return nil, err
	}
	webEnabled, webServer, webPort := parseProxyOutput(webOutput)

	secureOutput, err := shell.Exec("networksetup", "-getsecurewebproxy", interfaceDisplayName).ReadOutput()
	if err != nil {
		return nil, err
	}
	secureEnabled, secureServer, securePort := parseProxyOutput(secureOutput)

	var socksEnabled bool
	var socksServer string
	var socksPort int
	if sockOutput, sockErr := shell.Exec("networksetup", "-getsocksfirewallproxy", interfaceDisplayName).ReadOutput(); sockErr == nil {
		socksEnabled, socksServer, socksPort = parseProxyOutput(sockOutput)
	}

	bypassOutput, err := shell.Exec("networksetup", "-getproxybypassdomains", interfaceDisplayName).ReadOutput()
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
