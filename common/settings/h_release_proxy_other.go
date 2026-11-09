//go:build !darwin

package settings

// A platform without a system proxy (or one that never created one) has nothing to
// release, so the cross-platform entry point succeeds without doing anything.
func releaseSystemProxy() error {
	return nil
}
