package settings

type SystemProxy interface {
	IsEnabled() bool
	Enable() error
	Disable() error
	Close() error
}

// ReleaseSystemProxy hands the OS back to whatever was there before, without
// touching the tunnel that is still running.
//
// It exists for the one case closing the box cannot cover: the user leaves
// system-proxy mode while connected. Nothing is shutting down, so the inbound
// holding the proxy never gets closed and its Disable never runs, yet the setting
// they just picked says the OS should not be proxied. Releasing is a no-op when no
// system proxy of ours is active.
func ReleaseSystemProxy() error {
	return releaseSystemProxy()
}
