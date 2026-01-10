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

	// Lifecycle management for background goroutines.
	ctx    context.Context
	cancel context.CancelFunc
}

// NewClient initializes a client that handles provisioning and persistent storage.
func NewClient(serverAddr string, store qdef.CredentialStore) *Client {
	c := &Client{
		providers: make(map[string]DeviceProvider),
	}

	opts := qconn.ClientOpt{
		ServerHostname:  serverAddr,
		CredentialStore: store,
		Handler:         c, // Client implements qconn.StreamHandler
		Resolver:        qdef.NetResolver{},
	}
	c.qcClient = qconn.NewClient(opts)

	return c
}

// SetResolver sets a custom resolver for the internal qconn client.
func (c *Client) SetResolver(r qdef.Resolver) {
	c.qcClient.SetResolver(r)
}

// SetObserver sets a custom observer for the internal qconn client.
func (c *Client) SetObserver(o qdef.ClientObserver) {
	c.qcClient.SetObserver(o)
}

// Start begins background processes.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.mu.Unlock()
	return c.qcClient.Connect(ctx)
}

// SetDeviceProvider adds a dynamic device provider to the client.
// Must be called after Start() for timer providers to work correctly.
func (c *Client) SetDeviceProvider(name string, p DeviceProvider) {
	c.mu.Lock()
	c.providers[name] = p
	ctx := c.ctx
	c.mu.Unlock()

	if tp, ok := p.(*timerProvider); ok {
		if ctx == nil {
			ctx = context.Background()
		}
		go c.runTimerProvider(ctx, tp)
	}
}

func (c *Client) runTimerProvider(ctx context.Context, t *timerProvider) {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.UpdateDevices(ctx)
		}
	}
}

// Close gracefully disconnects and stops background goroutines.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
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

// ListMachines returns the current state of the entire network.
func (c *Client) ListMachines(ctx context.Context, includeUnprovisioned bool) ([]qdef.HostState, error) {
	target := qdef.Addr{
		Service: qdef.ServiceSystem,
		Type:    "list-machines",
	}

	req := qdef.ListMachinesReq{ShowUnprovisioned: includeUnprovisioned}
	var resp qdef.ListMachinesResp
	_, err := c.qcClient.Request(ctx, target, &req, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Hosts, nil
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
