package settings

import (
	"context"
	"strconv"
	"strings"

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

func (p *DarwinSystemProxy) Disable() error {
	interfaceDisplayName, err := getInterfaceDisplayName(p.interfaceName)
	if err != nil {
		return err
	}
	if p.previous != nil && p.displayName == interfaceDisplayName {
		err = p.restore(interfaceDisplayName, p.previous)
	} else {
		err = p.disableAll(interfaceDisplayName)
	}
	if err == nil {
		p.isEnabled = false
		p.previous = nil
	}
	return err
}

func (p *DarwinSystemProxy) routeUpdate(defaultInterface *control.Interface, flags int) {
	if !p.isEnabled || defaultInterface == nil {
		return
	}
	_ = p.update0()
}

func (p *DarwinSystemProxy) update0() error {
	newInterface := p.monitor.DefaultInterface()
	if p.interfaceName == newInterface.Name {
		return nil
	}
	if p.interfaceName != "" {
		_ = p.Disable()
	}
	p.interfaceName = newInterface.Name
	interfaceDisplayName, err := getInterfaceDisplayName(p.interfaceName)
	if err != nil {
		return err
	}
	p.displayName = interfaceDisplayName
	if p.previous == nil {
		p.previous, err = readDarwinProxyState(interfaceDisplayName)
		if err != nil {
			return err
		}
	}
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
	p.isEnabled = true
	return nil
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
