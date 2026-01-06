package anex

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kardianos/qconn/qdef"
	"github.com/quic-go/quic-go"
)

type contextKey int

const (
	identityKey contextKey = iota
)

// RoleConfig defines what a role can do.
type RoleConfig struct {
	Provides []string // Job types this role provides.
	SendsTo  []string // Job types this role can send to.
}

// Hub manages the routing of messages between clients and tracks network state.
type Hub struct {
	mu          sync.RWMutex
	activeConns sync.Map // Map of fingerprint -> *quic.Conn.
	hostStates  sync.Map // Map of fingerprint -> *qdef.Identity
	defaultWait time.Duration

	roleDefs             map[string]RoleConfig
	staticAuthorizations map[string][]string // fingerprint -> allowed roles
}

func NewHub(defaultWait time.Duration) *Hub {
	if defaultWait <= 0 {
		defaultWait = 10 * time.Second
	}
	h := &Hub{
		defaultWait:          defaultWait,
		roleDefs:             make(map[string]RoleConfig),
		staticAuthorizations: make(map[string][]string),
	}

	return h
}

// SetRoleDef configures a role's capabilities.
func (h *Hub) SetRoleDef(name string, config RoleConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.roleDefs[name] = config
}

// SetStaticAuthorization configures which roles a machine is allowed to have.
func (h *Hub) SetStaticAuthorization(fingerprint string, roles []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.staticAuthorizations[fingerprint] = roles
}

// AuthorizeRoles filters requested roles based on static configuration.
func (h *Hub) AuthorizeRoles(fingerprint string, hostname string, requested []string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	allowed, ok := h.staticAuthorizations[fingerprint]
	if !ok {
		allowed, ok = h.staticAuthorizations[hostname]
		if !ok {
			return nil
		}
	}

	var authorized []string
	allowedMap := make(map[string]bool)
	for _, r := range allowed {
		allowedMap[r] = true
	}

	for _, req := range requested {
		if allowedMap[req] {
			authorized = append(authorized, req)
		}
	}
	return authorized
}

func (h *Hub) canSend(senderRoles []string, jobType string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, roleName := range senderRoles {
		if def, ok := h.roleDefs[roleName]; ok {
			for _, targetJob := range def.SendsTo {
				if targetJob == jobType {
					return true
				}
			}
		}
	}
	return false
}

func (h *Hub) canProvide(receiverRoles []string, jobType string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, roleName := range receiverRoles {
		if def, ok := h.roleDefs[roleName]; ok {
			for _, providedJob := range def.Provides {
				if providedJob == jobType {
					return true
				}
			}
		}
	}
	return false
}

func (h *Hub) RegisterHandlers(r *qdef.StreamRouter) {
	qdef.Handle(r, qdef.ServiceSystem, "devices", h.handleDeviceUpdate)
	qdef.Handle(r, qdef.ServiceSystem, "list-hosts", h.handleListHosts)
}

// OnIdentityConnect implements qconn.StateListener.
func (h *Hub) OnIdentityConnect(id qdef.Identity, conn *quic.Conn) {
	h.activeConns.Store(id.Fingerprint, conn)
}

// OnIdentityDisconnect implements qconn.StateListener.
func (h *Hub) OnIdentityDisconnect(id qdef.Identity) {
	h.activeConns.Delete(id.Fingerprint)
}

// OnConnect implements qconn.StreamHandler.
func (h *Hub) OnConnect(conn *quic.Conn) {
}

// OnStateChange implements qconn.StateListener.
func (h *Hub) OnStateChange(id qdef.Identity, state qdef.ClientState) {
	// We might want to store more detailed state here, but for now just update identity if it's connected.
	if state == qdef.StateConnected || state == qdef.StateAuthorized {
		h.hostStates.Store(id.Fingerprint, &id)
	}
}

// GetConnectionByMachine returns the active connection for a given machine fingerprint.
func (h *Hub) GetConnectionByMachine(fingerprint string) (*quic.Conn, error) {
	val, ok := h.activeConns.Load(fingerprint)
	if !ok {
		return nil, fmt.Errorf("machine %s not connected", fingerprint)
	}
	return val.(*quic.Conn), nil
}

// ListHostStates returns the current state of all known hosts.
func (h *Hub) ListHostStates() []qdef.HostState {
	var states []qdef.HostState
	h.hostStates.Range(func(key, value interface{}) bool {
		id := value.(*qdef.Identity)
		_, online := h.activeConns.Load(id.Fingerprint)
		states = append(states, qdef.HostState{
			Identity: *id,
			Online:   online,
		})
		return true
	})
	return states
}

// Route directs a message to the target and returns the response.
func (h *Hub) Route(ctx context.Context, msg qdef.Message) (*qdef.Message, error) {
	deadline := time.Now().Add(h.defaultWait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	for {
		conn, err := h.findTarget(msg.Target)
		if err == nil {
			// Check if sender has permission to send this job type.
			senderRoles, ok := h.getSenderRoles(ctx)
			if ok && !h.canSend(senderRoles, msg.Target.Type) {
				return nil, fmt.Errorf("role %v not authorized to send job type %q", senderRoles, msg.Target.Type)
			}

			// Check if receiver has permission to provide this job type.
			receiverRoles := h.getReceiverRoles(msg.Target.Machine)
			if !h.canProvide(receiverRoles, msg.Target.Type) {
				return nil, fmt.Errorf("target %q not authorized to provide job type %q", msg.Target.Machine, msg.Target.Type)
			}

			return h.forward(ctx, conn, msg)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("target %v not available after timeout", msg.Target)
			}
		}
	}
}

func (h *Hub) findTarget(target qdef.Addr) (*quic.Conn, error) {
	return h.GetConnectionByMachine(target.Machine)
}

func (h *Hub) forward(ctx context.Context, conn *quic.Conn, msg qdef.Message) (*qdef.Message, error) {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	if err := cbor.NewEncoder(stream).Encode(msg); err != nil {
		return nil, err
	}

	var resp qdef.Message
	if err := cbor.NewDecoder(stream).Decode(&resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// Request is a high-level helper that handles ID generation and CBOR abstraction.
func (h *Hub) Request(ctx context.Context, target qdef.Addr, payload interface{}, response interface{}) error {
	rawPayload, err := cbor.Marshal(payload)
	if err != nil {
		return err
	}

	msg := qdef.Message{
		ID:      qdef.MessageID(time.Now().UnixNano()),
		Target:  target,
		Payload: rawPayload,
	}

	respMsg, err := h.Route(ctx, msg)
	if err != nil {
		return err
	}

	if respMsg.Error != "" {
		return fmt.Errorf("%s", respMsg.Error)
	}

	if response != nil {
		return cbor.Unmarshal(respMsg.Payload, response)
	}
	return nil
}

// Handle implements qdef.StreamHandler.
func (h *Hub) Handle(ctx context.Context, id qdef.Identity, msg qdef.Message, stream qdef.Stream) {
	ctx = context.WithValue(ctx, identityKey, id)

	if msg.Target.Service == qdef.ServiceUser {
		resp, err := h.Route(ctx, msg)
		if err != nil {
			errorMsg := qdef.Message{
				ID:    msg.ID,
				Error: err.Error(),
			}
			cbor.NewEncoder(stream).Encode(errorMsg)
			return
		}

		if err := cbor.NewEncoder(stream).Encode(resp); err != nil {
			return
		}
		return
	}

	resp := qdef.Message{
		ID:    msg.ID,
		Error: fmt.Sprintf("no handler for %s:%s", msg.Target.Service, msg.Target.Type),
	}
	cbor.NewEncoder(stream).Encode(resp)
}

func (h *Hub) getSenderRoles(ctx context.Context) ([]string, bool) {
	id, ok := ctx.Value(identityKey).(qdef.Identity)
	if !ok {
		return nil, false
	}
	return id.Roles, true
}

func (h *Hub) getReceiverRoles(fingerprint string) []string {
	if val, ok := h.hostStates.Load(fingerprint); ok {
		return val.(*qdef.Identity).Roles
	}
	return nil
}

func (h *Hub) handleDeviceUpdate(ctx context.Context, id qdef.Identity, req *qdef.DeviceUpdateRequest) (*struct{}, error) {
	id.Type = req.Type
	id.Devices = req.Devices

	h.hostStates.Store(id.Fingerprint, &id)

	return &struct{}{}, nil
}

func (h *Hub) handleListHosts(ctx context.Context, id qdef.Identity, _ *struct{}) (*[]qdef.HostState, error) {
	hosts := h.ListHostStates()
	return &hosts, nil
}
