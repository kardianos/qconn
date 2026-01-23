//go:build windows

package qstore

// Default paths for credential storage on Windows.
// Uses registry with HKEY_CURRENT_USER for admin and HKEY_LOCAL_MACHINE for services.
const (
	DefaultAdminStorePath   = `CU\SOFTWARE\qconn\admin`
	DefaultServiceStorePath = `LM\SOFTWARE\qconn\client`
)
