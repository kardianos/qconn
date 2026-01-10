package qmanage

import (
	"fmt"
	"regexp"
)

// validAppNameRegex matches valid application names.
// Only alphanumeric characters, hyphens, and underscores are allowed.
// Must start with an alphanumeric character and be 1-64 characters long.
var validAppNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// validateAppName validates that an application name is safe for use in paths.
// This prevents path traversal attacks and registry key injection.
func validateAppName(appName string) error {
	if appName == "" {
		return fmt.Errorf("app name cannot be empty")
	}
	if !validAppNameRegex.MatchString(appName) {
		return fmt.Errorf("invalid app name %q: must contain only alphanumeric characters, hyphens, and underscores, start with alphanumeric, and be 1-64 characters", appName)
	}
	return nil
}
