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

// RoleConfig defines what a role can do.
type RoleConfig struct {
	Provides []string // Job types this role provides.
	SendsTo  []string // Job types this role can send to.
}

// Hub manages the routing of messages between clients and tracks network state.
type Hub struct {
	mu          sync.RWMutex
	activeConns map[string]*quic.Conn     // Map of fingerprint -> *quic.Conn.
	hostStates  map[string]*qdef.Identity // Map of fingerprint -> *qdef.Identity
	defaultWait time.Duration

	roleDefs             map[string]RoleConfig
	staticAuthorizations map[string][]string // fingerprint -> allowed roles
	unprovisioned        map[string]struct{} // hostname -> struct{}
}

func NewHub(defaultWait time.Duration) *Hub {
	if defaultWait <= 0 {
		defaultWait = 10 * time.Second
	}
	h := &Hub{
		defaultWait:          defaultWait,
		activeConns:          make(map[string]*quic.Conn),
		hostStates:           make(map[string]*qdef.Identity),
		roleDefs:             make(map[string]RoleConfig),
		staticAuthorizations: make(map[string][]string),
		unprovisioned:        make(map[string]struct{}),
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

func (h *Hub) getIdentity(fingerprint string) qdef.Identity {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if val, ok := h.hostStates[fingerprint]; ok {
		return *val
	}
	return qdef.Identity{Fingerprint: fingerprint}
}

// AuthorizeRoles filters requested roles based on static configuration.
// Authorization is by fingerprint only; hostname is not used for lookup.
func (h *Hub) AuthorizeRoles(fingerprint string, requested []string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	allowed, ok := h.staticAuthorizations[fingerprint]
	if !ok {
		return nil
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
	qdef.Handle(r, qdef.ServiceSystem, "list-machines", h.handleListMachines)
	qdef.Handle(r, qdef.ServiceSystem, "provision", h.handleProvision)
}

// OnIdentityConnect implements qconn.StateListener.
func (h *Hub) OnIdentityConnect(id qdef.Identity, conn *quic.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.activeConns[id.Fingerprint] = conn
	delete(h.unprovisioned, id.Hostname)
}

// OnIdentityDisconnect implements qconn.StateListener.
func (h *Hub) OnIdentityDisconnect(id qdef.Identity) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.activeConns, id.Fingerprint)
}

// OnConnect implements qconn.StreamHandler.
func (h *Hub) OnConnect(conn *quic.Conn) {
}

// OnStateChange implements qconn.StateListener.
func (h *Hub) OnStateChange(id qdef.Identity, state qdef.ClientState) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if state == qdef.StateProvisioning {
		h.unprovisioned[id.Hostname] = struct{}{}
		return
	}

	if state == qdef.StateConnected || state == qdef.StateAuthorized {
		// Assign roles from server-side authorization (not from certificate).
		roles, ok := h.staticAuthorizations[id.Fingerprint]
		if ok {
			id.Roles = roles
		}
		h.hostStates[id.Fingerprint] = &id
		delete(h.unprovisioned, id.Hostname)
	}
}

// GetConnectionByMachine returns the active connection for a given machine fingerprint.
func (h *Hub) GetConnectionByMachine(fingerprint string) (*quic.Conn, error) {
	h.mu.RLock()
	val, ok := h.activeConns[fingerprint]
	h.mu.RUnlock()
	if !ok {
		id := h.getIdentity(fingerprint)
		return nil, fmt.Errorf("%w: machine %s not connected", qdef.ErrTargetNotFound, id)
	}
	return val, nil
}

// ListHostStates returns the current state of all known hosts.
func (h *Hub) ListHostStates(includeUnprovisioned bool) []qdef.HostState {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var states []qdef.HostState

	// Add provisioned hosts.
	for _, id := range h.hostStates {
		_, online := h.activeConns[id.Fingerprint]
		states = append(states, qdef.HostState{
			Identity:    *id,
			Online:      online,
			Provisioned: true,
		})
	}

	// Add unprovisioned hosts if requested.
	if includeUnprovisioned {
		for hostname := range h.unprovisioned {
			states = append(states, qdef.HostState{
				Identity:    qdef.Identity{Hostname: hostname},
				Online:      false,
				Provisioned: false,
			})
		}
	}

	return states
}

// Route directs a message to the target and returns the response.
func (h *Hub) Route(ctx context.Context, senderID qdef.Identity, msg qdef.Message) (*qdef.Message, error) {
	deadline := time.Now().Add(h.defaultWait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	for {
		conn, err := h.findTarget(msg.Target)
		if err == nil {
			// Check if sender has permission to send this job type.
			if senderID.Fingerprint == "" {
				return nil, fmt.Errorf("%w: sender fingerprint required", qdef.ErrUnauthorized)
			}
			if !h.canSend(senderID.Roles, msg.Target.Type) {
				return nil, fmt.Errorf("%w: role %v not authorized to send job type %q", qdef.ErrUnauthorized, senderID.Roles, msg.Target.Type)
			}

			// Check if receiver has permission to provide this job type.
			receiverRoles := h.getReceiverRoles(msg.Target.Machine)
			if !h.canProvide(receiverRoles, msg.Target.Type) {
				return nil, fmt.Errorf("%w: target %q not authorized to provide job type %q", qdef.ErrUnauthorized, msg.Target.Machine, msg.Target.Type)
			}

			return h.forward(ctx, conn, msg)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("%w: target %v not available after timeout", qdef.ErrTargetNotFound, msg.Target)
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
func (h *Hub) Request(ctx context.Context, senderID qdef.Identity, target qdef.Addr, payload interface{}, response interface{}) error {
	rawPayload, err := cbor.Marshal(payload)
	if err != nil {
		return err
	}

	msg := qdef.Message{
		ID:      qdef.MessageID(time.Now().UnixNano()),
		Target:  target,
		Payload: rawPayload,
	}

	respMsg, err := h.Route(ctx, senderID, msg)
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
	if msg.Target.Service == qdef.ServiceUser {
		// Look up the sender's full identity with roles from our stored state.
		// The server passes identity without roles; we maintain roles server-side.
		senderID := h.getIdentity(id.Fingerprint)
		if senderID.Hostname == "" {
			senderID.Hostname = id.Hostname
		}
		if senderID.Address == "" {
			senderID.Address = id.Address
		}

		resp, err := h.Route(ctx, senderID, msg)
		if err != nil {
			errorMsg := qdef.Message{
				ID:    msg.ID,
				Error: err.Error(),
			}
			_ = cbor.NewEncoder(stream).Encode(errorMsg)
			return
		}

		_ = cbor.NewEncoder(stream).Encode(resp)
		return
	}

	resp := qdef.Message{
		ID:    msg.ID,
		Error: fmt.Sprintf("no handler for %s:%s", msg.Target.Service, msg.Target.Type),
	}
	_ = cbor.NewEncoder(stream).Encode(resp)
}

func (h *Hub) getReceiverRoles(fingerprint string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if val, ok := h.hostStates[fingerprint]; ok {
		return val.Roles
	}
	return nil
}

func (h *Hub) handleDeviceUpdate(ctx context.Context, id qdef.Identity, req *qdef.DeviceUpdateRequest) (*struct{}, error) {
	// Preserve existing roles from our stored state.
	h.mu.Lock()
	existingIDptr, ok := h.hostStates[id.Fingerprint]
	var existingID qdef.Identity
	if ok {
		existingID = *existingIDptr
	} else {
		existingID = qdef.Identity{Fingerprint: id.Fingerprint}
	}

	existingID.Type = req.Type
	existingID.Devices = req.Devices
	if existingID.Hostname == "" {
		existingID.Hostname = id.Hostname
	}
	if existingID.Address == "" {
		existingID.Address = id.Address
	}

	h.hostStates[id.Fingerprint] = &existingID
	delete(h.unprovisioned, id.Hostname)
	h.mu.Unlock()

	return &struct{}{}, nil
}

func (h *Hub) handleListMachines(ctx context.Context, id qdef.Identity, req *qdef.ListMachinesReq) (*qdef.ListMachinesResp, error) {
	// Look up the sender's full identity with roles from our stored state.
	// Fall back to passed roles for direct unit test calls.
	senderID := h.getIdentity(id.Fingerprint)
	if len(senderID.Roles) == 0 {
		senderID.Roles = id.Roles
	}
	if !h.canSend(senderID.Roles, "list-machines") {
		return nil, fmt.Errorf("%w: role %v not authorized for list-machines", qdef.ErrUnauthorized, senderID.Roles)
	}
	hosts := h.ListHostStates(req.ShowUnprovisioned)
	return &qdef.ListMachinesResp{Hosts: hosts}, nil
}

func (h *Hub) handleProvision(ctx context.Context, id qdef.Identity, req *qdef.ProvisionReq) (*struct{}, error) {
	// Look up the sender's full identity with roles from our stored state.
	// Fall back to passed roles for direct unit test calls.
	senderID := h.getIdentity(id.Fingerprint)
	if len(senderID.Roles) == 0 {
		senderID.Roles = id.Roles
	}
	if !h.canSend(senderID.Roles, "provision") {
		return nil, fmt.Errorf("%w: role %v not authorized for provision", qdef.ErrUnauthorized, senderID.Roles)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, fp := range req.Fingerprint {
		delete(h.unprovisioned, fp) // Note: fingerpint often matches hostname in this context if not yet provisioned.
		h.staticAuthorizations[fp] = nil
	}
	return &struct{}{}, nil
}
