package qstore

// NS provides namespaced views of a DataStore.
// It allows partitioning a single store into logical sections
// by prefixing keys with a namespace.
type NS struct {
	store DataStore
}

// NewNS creates a namespace manager for the given store.
func NewNS(store DataStore) *NS {
	return &NS{store: store}
}

// Add returns a DataStore that prefixes all keys with the given namespace.
// Keys are prefixed as "namespace/key".
func (ns *NS) Add(namespace string) DataStore {
	return &namespacedStore{
		store:  ns.store,
		prefix: namespace + "/",
	}
}

// namespacedStore wraps a DataStore with a key prefix.
type namespacedStore struct {
	store  DataStore
	prefix string
}

func (s *namespacedStore) Get(key string, decrypt bool) ([]byte, error) {
	return s.store.Get(s.prefix+key, decrypt)
}

func (s *namespacedStore) Set(key string, encrypt bool, value []byte) error {
	return s.store.Set(s.prefix+key, encrypt, value)
}

func (s *namespacedStore) Path() string {
	return s.store.Path()
}
