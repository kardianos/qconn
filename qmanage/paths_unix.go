//go:build !windows

package qmanage

import "path/filepath"

func defaultClientDir(appName string) string {
	return filepath.Join("/var/lib", appName, "client")
}

func defaultServerDir(appName string) string {
	return filepath.Join("/var/lib", appName, "server")
}
