//go:build !windows

package qmanage

// NewClientStore creates a new file-based credential store.
func NewClientStore(cfg ClientStoreConfig, appName string) (ClientStore, error) {
	if err := validateAppName(appName); err != nil {
		return nil, err
	}
	cfg.Dir = defaultClientDir(appName)
	return newFileCredentialStore(cfg)
}

// NewClientStoreWithDir creates a new file-based credential store at the specified directory.
func NewClientStoreWithDir(cfg ClientStoreConfig) (*FileCredentialStore, error) {
	return newFileCredentialStore(cfg)
}
