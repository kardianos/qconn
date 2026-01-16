package qconn

import (
	"context"
	"time"

	"github.com/kardianos/qconn/qdef"
)

// DeviceProvider defines an interface for providing a dynamic list of devices.
type DeviceProvider interface {
	Devices(ctx context.Context) []qdef.DeviceInfo
}

// StaticDevices returns a provider that always returns the same list of devices.
func StaticDevices(devices ...qdef.DeviceInfo) DeviceProvider {
	return &staticProvider{devices: devices}
}

type staticProvider struct {
	devices []qdef.DeviceInfo
}

func (s *staticProvider) Devices(ctx context.Context) []qdef.DeviceInfo {
	return s.devices
}

// TimerDevices returns a provider that polls for devices at a given interval.
// The provided function is called periodically to get the current device list.
// Call the returned cancel function to stop the timer.
func TimerDevices(ctx context.Context, c *Client, interval time.Duration, fn func(ctx context.Context) []qdef.DeviceInfo) (DeviceProvider, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	tp := &timerProvider{
		interval: interval,
		fn:       fn,
	}
	go runTimerProvider(ctx, c, tp)
	return tp, cancel
}

type timerProvider struct {
	interval time.Duration
	fn       func(ctx context.Context) []qdef.DeviceInfo
}

func (t *timerProvider) Devices(ctx context.Context) []qdef.DeviceInfo {
	return t.fn(ctx)
}

func runTimerProvider(ctx context.Context, c *Client, t *timerProvider) {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			devices := t.fn(ctx)
			c.SetDevices(devices)
			_ = c.TriggerUpdateDevices(ctx)
		}
	}
}

// Handle registers a typed handler on the client's router for user-level services.
func Handle[Req, Resp any](c *Client, name string, h qdef.HandleFunc[Req, Resp]) {
	qdef.Handle(&c.Router, qdef.ServiceUser, name, h)
}

// Request sends a typed request to a target address and returns a typed response.
func Request[Req, Resp any](c *Client, ctx context.Context, target qdef.Addr, req *Req) (*Resp, error) {
	var resp Resp
	_, err := c.Request(ctx, target, req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
