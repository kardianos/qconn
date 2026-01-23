//go:build !windows

package qstore

// Default paths for credential storage on non-Windows systems.
const (
	DefaultAdminStorePath   = "$HOME/.config/qconn/admin"
	DefaultServiceStorePath = "/etc/qconn/client"
)
