package main

import (
	"github.com/kardianos/qconn"
	"github.com/kardianos/qconn/qstore"
)

// adminCredentialStore wraps qconn.ClientCredential with server storage.
type adminCredentialStore struct {
	*qconn.ClientCredential
}

func newAdminCredentialStore(store qstore.DataStore, hostname, provisionToken string) (*adminCredentialStore, error) {
	cred, err := qconn.NewClientCredential(qconn.ClientCredentialConfig{
		Store:          store,
		Hostname:       hostname,
		ProvisionToken: provisionToken,
	})
	if err != nil {
		return nil, err
	}

	return &adminCredentialStore{
		ClientCredential: cred,
	}, nil
}

// GetServer returns the stored server address.
func (s *adminCredentialStore) GetServer() string {
	data, _ := s.Store().Get("server", false)
	return string(data)
}

// SetServer stores the server address.
func (s *adminCredentialStore) SetServer(server string) error {
	return s.Store().Set("server", false, []byte(server))
}

// Path returns the storage path for display.
func (s *adminCredentialStore) Path() string {
	return s.Store().Path()
}
