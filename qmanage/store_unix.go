//go:build !windows

package qmanage

// NewClientStore creates a new file-based credential store.
func NewClientStore(appName string) (ClientStore, error) {
	if err := validateAppName(appName); err != nil {
		return nil, err
	}
	return NewClientStoreWithDir(defaultClientDir(appName))
}

// NewClientStoreWithDir creates a new file-based credential store at the specified directory.
func NewClientStoreWithDir(dir string) (*FileCredentialStore, error) {
	return newFileCredentialStore(dir)
}
