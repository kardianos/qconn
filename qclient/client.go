package qclient

import (
	"context"
	"sync"
	"time"

	"github.com/kardianos/qconn/qdef"

	"github.com/kardianos/qconn/qconn"
	"github.com/quic-go/quic-go"
)

// Registration allows a registered handler to update its devices independently.
type Registration struct {
	client   *Client
	name     string
	provider DeviceProvider
}

// UpdateDevices triggers a refresh of devices for this registration.
func (r *Registration) UpdateDevices(ctx context.Context) error {
	return r.client.UpdateDevices(ctx)
}

// DeviceProvider defines an interface for providing a dynamic list of devices.
type DeviceProvider interface {
	Devices(ctx context.Context) []string
}

// StaticDevices returns a provider that always returns the same list of devices.
func StaticDevices(devices ...string) DeviceProvider {
	return &staticProvider{devices: devices}
}

type staticProvider struct {
	devices []string
}

func (s *staticProvider) Devices(ctx context.Context) []string {
	return s.devices
}

// TimerDevices returns a provider that polls for devices at a given interval.
func TimerDevices(interval time.Duration, fn func(ctx context.Context) []string) DeviceProvider {
	return &timerProvider{
		interval: interval,
		fn:       fn,
	}
}

type timerProvider struct {
	interval time.Duration
	fn       func(ctx context.Context) []string
}

func (t *timerProvider) Devices(ctx context.Context) []string {
	return t.fn(ctx)
}

// Client is a high-level client for the qconn network.
type Client struct {
	qcClient  *qconn.Client
	mu        sync.RWMutex
	providers map[string]DeviceProvider
}

// NewClient initializes a client that handles provisioning and persistent storage.
func NewClient(serverAddr string, store qconn.CredentialStore) *Client {
	c := &Client{
		providers: make(map[string]DeviceProvider),
	}

	opts := qconn.ClientOpt{
		ServerHostname:  serverAddr,
		CredentialStore: store,
		Handler:         c, // Client implements qconn.StreamHandler
		Resolver:        qconn.NetResolver{},
	}
	c.qcClient = qconn.NewClient(opts)

	return c
}

// Start begins background processes.
func (c *Client) Start(ctx context.Context) error {
	return c.qcClient.Connect(ctx)
}

// SetDeviceProvider adds a dynamic device provider to the client.
func (c *Client) SetDeviceProvider(name string, p DeviceProvider) {
	c.mu.Lock()
	c.providers[name] = p
	c.mu.Unlock()

	if tp, ok := p.(*timerProvider); ok {
		go c.runTimerProvider(tp)
	}
}

func (c *Client) runTimerProvider(t *timerProvider) {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()
	for range ticker.C {
		_ = c.UpdateDevices(context.Background())
	}
}

// Close gracefully disconnects.
func (c *Client) Close() error {
	c.qcClient.Close()
	return nil
}

// Handle registers a user-level service and returns a registration object.
func Handle[Req, Resp any](c *Client, name string, p DeviceProvider, h qdef.HandleFunc[Req, Resp]) *Registration {
	qdef.Handle(&c.qcClient.Router, qdef.ServiceUser, name, h)
	if p != nil {
		c.mu.Lock()
		c.providers[name] = p
		c.mu.Unlock()
	}

	return &Registration{client: c, name: name, provider: p}
}

// Request sends a typed request to a target address and returns a typed response.
func Request[Req, Resp any](c *Client, ctx context.Context, target qdef.Addr, req *Req) (*Resp, error) {
	var resp Resp
	_, err := c.qcClient.Request(ctx, target, req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListDevices returns the current state of the entire network.
func (c *Client) ListDevices(ctx context.Context) ([]qdef.HostState, error) {
	target := qdef.Addr{
		Service: qdef.ServiceSystem,
		Type:    "list-hosts",
	}

	var hosts []qdef.HostState
	_, err := c.qcClient.Request(ctx, target, nil, &hosts)
	if err != nil {
		return nil, err
	}
	return hosts, nil
}

func (c *Client) RegisterHandlers(r *qdef.StreamRouter) {
	// No-op by default, handlers are added via Handle function.
}

// Handle (from qconn.StreamHandler) is a no-op as RPC dispatch is handled by the transport.
func (c *Client) Handle(ctx context.Context, id qdef.Identity, msg qdef.Message, stream qdef.Stream) {
}

// OnConnect (from qconn.StreamHandler) triggers device updates.
func (c *Client) OnConnect(conn *quic.Conn) {
	_ = c.UpdateDevices(context.Background())
}

// UpdateDevices triggers a manual update of the devices across all handlers and providers.
func (c *Client) UpdateDevices(ctx context.Context) error {
	c.mu.RLock()
	deviceMap := make(map[string]struct{})

	// Devices from providers.
	for _, p := range c.providers {
		for _, d := range p.Devices(ctx) {
			deviceMap[d] = struct{}{}
		}
	}
	c.mu.RUnlock()

	devices := make([]string, 0, len(deviceMap))
	for d := range deviceMap {
		devices = append(devices, d)
	}

	c.qcClient.SetDevices(devices)
	return c.qcClient.TriggerUpdateDevices(ctx)
}
