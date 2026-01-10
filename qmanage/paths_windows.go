//go:build windows

package qmanage

import (
	"os"
	"path/filepath"
)

func defaultClientDir(appName string) string {
	// On Windows, client data is stored in registry, so this returns empty.
	// This function is only used for file-based storage on Unix.
	return ""
}

func defaultServerDir(appName string) string {
	programData := os.Getenv("PROGRAMDATA")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, appName, "server")
}

func registryKeyPath(appName string) string {
	return `SOFTWARE\` + appName + `\client`
}
