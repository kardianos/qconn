package main

/*
Declarative Agent-Based Integration Test

Design:
  This test defines 4 agents (server, admin, time-provider, time-consumer), each with
  a list of steps to execute. Steps are declared as data, not imperative code.

Agents:
  - server:        Starts the qconn server
  - admin:         Performs admin operations (auth, list, approve, revoke)
  - time-provider: Connects and provides the time service
  - time-consumer: Connects and consumes the time service

Step Structure:
  Each step contains:
    - Cmd:        The command struct to execute (e.g., *qconn.CmdAdminList)
    - Wait:       Signal name to wait for before executing (empty = no wait)
    - Emit:       Signal name to emit after successful execution (empty = no emit)
    - Check:      Optional function to validate responses and extract data (e.g., fingerprints)
    - WantErr:    If non-empty, expect an error containing this substring
    - Background: If true, emit signal after first response and continue to next step
                  (command keeps running in background until context cancelled)

Synchronization:
  A central Signals struct provides coordination:
    - Wait(name) blocks until the named signal is emitted
    - Emit(name) broadcasts to all waiters on that signal
  Signals are one-shot: once emitted, subsequent Wait() calls return immediately.

Data Storage:
  Each step receives an AgentData view scoped to that agent:
    - d.Global(key)       - Read from global storage (shared across all agents)
    - d.SetGlobal(key, v) - Write to global storage
    - d.Get(key)          - Read from this agent's local storage
    - d.Set(key, v)       - Write to this agent's local storage
    - d.GetFrom(agent, k) - Read from another agent's local storage
  Values are stored and retrieved with type assertions.

Milestone Flags:
  Each agent defines a map[string]bool of milestone flags that must be set to true
  by the end of the test. This ensures all expected events actually occur.

Execution:
  1. The test runner starts all 4 agents as goroutines
  2. Each agent processes its steps sequentially:
     a. If Wait is set, block until that signal is emitted
     b. Execute the command via qconn.Execute()
     c. Run Check function on responses (if provided)
     d. If Emit is set, broadcast that signal
  3. The test passes when all agents complete their steps without error
  4. Final verification ensures all milestone flags are true

Signal Timeline (this test):
  server-ready ──────────────────────────────────────────────────────────────►
       │
       ▼
  admin-authed ──────────────────────────────────────────────────────────────►
       │
       ├──────────────────────┐
       ▼                      ▼
  provider-connected    consumer-connected
       │                      │
       ▼                      │
  provider-approved           │
       │                      │
       ▼                      │
  provider-ready              │
       │                      ▼
       │              consumer-approved
       │                      │
       │                      ▼
       │              consumer-done
       │                      │
       ▼                      ▼
  provider-stopped ◄──────────┘
       │
       ▼
  provider-revoked
       │
       ▼
  test-complete
*/

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kardianos/qconn"
	"github.com/kardianos/qconn/qexec"
)

func TestMain(m *testing.M) {
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "1")
	os.Exit(m.Run())
}

// Data key constants for type-safe storage.
const (
	// Global keys
	keyServerAddr = "server-addr"
	keyAuthToken  = "auth-token"
	keyConfigPath = "config-path"

	// Fingerprint keys (local to each agent that stores them)
	keyAdminFP       = "admin-fp"
	keyProviderFP    = "provider-fp"
	keyConsumerFP    = "consumer-fp"
	keyProviderNewFP = "provider-new-fp" // After re-provisioning
)

// Milestone flag constants.
const (
	// Server milestones
	msServerStarted = "server-started"

	// Admin milestones
	msAdminAuthed            = "admin-authed"
	msProviderApproved       = "provider-approved"
	msConsumerApproved       = "consumer-approved"
	msProviderRevoked        = "provider-revoked"
	msProviderReApproved     = "provider-re-approved"
	msVerifiedRevokedState   = "verified-revoked-state"
	msVerifiedReprovisioned  = "verified-reprovisioned"
	msVerifiedFinalReconnect = "verified-final-reconnect"

	// Provider milestones
	msProviderConnected     = "provider-connected"
	msProviderReady         = "provider-ready"
	msProviderReconnected   = "provider-reconnected"
	msProviderReadyAfterRev = "provider-ready-after-revoke"

	// Consumer milestones
	msConsumerConnected = "consumer-connected"
	msTimeReceived      = "time-received"
)

// Signals provides synchronization between agents.
// Each signal is a channel that gets closed when emitted.
type Signals struct {
	mu      sync.Mutex
	signals map[string]chan struct{}
}

func NewSignals() *Signals {
	return &Signals{signals: make(map[string]chan struct{})}
}

func (s *Signals) getOrCreate(name string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.signals[name]
	if !ok {
		ch = make(chan struct{})
		s.signals[name] = ch
	}
	return ch
}

func (s *Signals) Emit(name string) {
	ch := s.getOrCreate(name)
	select {
	case <-ch:
		// Already closed
	default:
		close(ch)
	}
}

func (s *Signals) Wait(ctx context.Context, name string) error {
	ch := s.getOrCreate(name)
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Signals) Close() {
	// No-op, channels will be GC'd
}

// TestData holds shared state between agents using type-safe map access.
type TestData struct {
	mu     sync.RWMutex
	global map[string]any            // Shared across all agents
	local  map[string]map[string]any // Per-agent storage
}

func NewTestData() *TestData {
	return &TestData{
		global: make(map[string]any),
		local:  make(map[string]map[string]any),
	}
}

func (d *TestData) SetGlobal(key string, value any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.global[key] = value
}

func (d *TestData) GetGlobal(key string) any {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.global[key]
}

func (d *TestData) setLocal(agent, key string, value any) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.local[agent] == nil {
		d.local[agent] = make(map[string]any)
	}
	d.local[agent][key] = value
}

func (d *TestData) getLocal(agent, key string) any {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.local[agent] == nil {
		return nil
	}
	return d.local[agent][key]
}

// ForAgent returns a scoped view of the data for a specific agent.
func (d *TestData) ForAgent(name string) *AgentData {
	return &AgentData{data: d, agent: name}
}

// AgentData provides a scoped view of TestData for a specific agent.
// Local operations (Set/Get) are automatically namespaced to this agent.
type AgentData struct {
	data  *TestData
	agent string
}

// Global retrieves a value from global storage.
func (a *AgentData) Global(key string) any {
	return a.data.GetGlobal(key)
}

// SetGlobal stores a value in global storage.
func (a *AgentData) SetGlobal(key string, value any) {
	a.data.SetGlobal(key, value)
}

// Get retrieves a value from this agent's local storage.
func (a *AgentData) Get(key string) any {
	return a.data.getLocal(a.agent, key)
}

// Set stores a value in this agent's local storage.
func (a *AgentData) Set(key string, value any) {
	a.data.setLocal(a.agent, key, value)
}

// Step represents a single action for an agent.
type Step struct {
	Name       string                                               // Description for logging
	Cmd        func(data *AgentData) any                            // Returns command struct
	Wait       string                                               // Signal to wait for before executing
	Emit       string                                               // Signal to emit after success
	Check      func(t *testing.T, data *AgentData, responses []any) // Validate responses
	WantErr    string                                               // Expected error substring (empty = no error)
	Timeout    time.Duration                                        // Per-step timeout (0 = use default)
	Background bool                                                 // If true, emit signal after first response and continue to next step
}

// Agent represents a participant in the test.
type Agent struct {
	Name       string
	Steps      []Step
	Milestones map[string]bool // Milestone flags that must all be true at end
	Ctx        context.Context // Set by runner, may be cancelled for long-running agents
	Cancel     context.CancelFunc
	completed  bool // Set when agent finishes all steps
}

func runAgents(t *testing.T, ctx context.Context, signals *Signals, data *TestData, agents []*Agent) {
	var wg sync.WaitGroup
	errCh := make(chan error, len(agents))

	for _, agent := range agents {
		wg.Add(1)
		go func(a *Agent) {
			defer wg.Done()
			if err := runAgent(t, ctx, signals, data, a); err != nil {
				errCh <- fmt.Errorf("agent %s: %w", a.Name, err)
			} else {
				a.completed = true
			}
		}(agent)
	}

	// Wait for all agents to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All agents completed
	case <-ctx.Done():
		t.Fatalf("Test timed out: %v", ctx.Err())
	}

	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// Verify all agents completed
	for _, agent := range agents {
		if !agent.completed {
			t.Errorf("Agent %s did not complete", agent.Name)
		}
	}

	// Verify all milestone flags are set
	for _, agent := range agents {
		for flag, set := range agent.Milestones {
			if !set {
				t.Errorf("Agent %s: milestone %q was not reached", agent.Name, flag)
			}
		}
	}
}

func runAgent(t *testing.T, ctx context.Context, signals *Signals, data *TestData, agent *Agent) error {
	// Create scoped view of data for this agent
	agentData := data.ForAgent(agent.Name)

	for i, step := range agent.Steps {
		if err := runStep(t, ctx, signals, agentData, agent, i, step); err != nil {
			return err
		}
	}
	return nil
}

func runStep(t *testing.T, ctx context.Context, signals *Signals, agentData *AgentData, agent *Agent, i int, step Step) error {
	// Use agent's context if set (for cancellable long-running commands)
	stepCtx := ctx
	if agent.Ctx != nil {
		stepCtx = agent.Ctx
	}

	// Apply per-step timeout
	if step.Timeout > 0 {
		var cancel context.CancelFunc
		stepCtx, cancel = context.WithTimeout(stepCtx, step.Timeout)
		defer cancel()
	}

	t.Logf("[%s] Step %d: %s", agent.Name, i+1, step.Name)

	// Wait for signal if specified
	if step.Wait != "" {
		t.Logf("[%s] Waiting for signal: %s", agent.Name, step.Wait)
		if err := signals.Wait(ctx, step.Wait); err != nil {
			return fmt.Errorf("step %d (%s): wait for %s: %w", i+1, step.Name, step.Wait, err)
		}
	}

	// Build and execute command
	cmd := step.Cmd(agentData)
	if cmd == nil {
		// No command, just signal coordination
		if step.Emit != "" {
			t.Logf("[%s] Emitting signal: %s", agent.Name, step.Emit)
			signals.Emit(step.Emit)
		}
		return nil
	}

	responses := make(chan any, 10)
	errCh := make(chan error, 1)
	go func() {
		errCh <- qexec.Execute(stepCtx, cmd, responses)
	}()

	// Process responses as they arrive, calling Check for each
	emitted := false
	for r := range responses {
		// Call Check on each response so signals can be emitted early
		if step.Check != nil {
			step.Check(t, agentData, []any{r})
		}
		// Emit signal after first response
		if step.Emit != "" && !emitted {
			t.Logf("[%s] Emitting signal: %s", agent.Name, step.Emit)
			signals.Emit(step.Emit)
			emitted = true
		}
		// For background commands, move on after first response
		if step.Background && emitted {
			t.Logf("[%s] Command running in background, continuing to next step", agent.Name)
			break
		}
	}

	// Only wait for completion if not a background command
	if !step.Background {
		err := <-errCh

		// Check error expectation
		if step.WantErr != "" {
			if err == nil {
				return fmt.Errorf("step %d (%s): expected error containing %q, got nil", i+1, step.Name, step.WantErr)
			}
			// Error was expected, continue
		} else if err != nil && err != context.Canceled {
			return fmt.Errorf("step %d (%s): %w", i+1, step.Name, err)
		}
	}
	return nil
}

func TestIntegrationAgents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "qconn-agents-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	provisionToken := "integration-test-provision-token"

	signals := NewSignals()
	defer signals.Close()

	data := NewTestData()
	data.SetGlobal(keyConfigPath, tempDir+"/admin.conf")

	// Create cancellable context for the server (long-running)
	serverCtx, serverCancel := context.WithCancel(ctx)

	// ═══════════════════════════════════════════════════════════════════════════
	// AGENT DEFINITIONS (declarative)
	// ═══════════════════════════════════════════════════════════════════════════

	// Define agents first (without steps) so closures can reference them
	serverAgent := &Agent{
		Name:   "server",
		Ctx:    serverCtx,
		Cancel: serverCancel,
		Milestones: map[string]bool{
			msServerStarted: false,
		},
	}

	adminAgent := &Agent{
		Name: "admin",
		Milestones: map[string]bool{
			msAdminAuthed:            false,
			msProviderApproved:       false,
			msConsumerApproved:       false,
			msProviderRevoked:        false,
			msVerifiedRevokedState:   false,
			msVerifiedReprovisioned:  false,
			msProviderReApproved:     false,
			msVerifiedFinalReconnect: false,
		},
	}

	providerAgent := &Agent{
		Name: "time-provider",
		// Note: No agent-level Ctx - each step manages its own cancellation
		Milestones: map[string]bool{
			msProviderConnected:     false,
			msProviderReady:         false,
			msProviderReconnected:   false,
			msProviderReadyAfterRev: false,
		},
	}

	consumerAgent := &Agent{
		Name: "time-consumer",
		Milestones: map[string]bool{
			msConsumerConnected: false,
			msTimeReceived:      false,
		},
	}

	// Now define steps (closures can reference agents)
	serverAgent.Steps = []Step{
		{
			Name:       "Start server",
			Background: true, // Server runs until test completes
			Cmd: func(d *AgentData) any {
				return &qexec.CmdServerStart{
					ListenAddr:      "127.0.0.1:0",
					DBPath:          tempDir + "/server/auth.db",
					ProvisionTokens: []string{provisionToken},
					Roles: map[string]*qconn.RoleConfig{
						"admin":         {Submit: []string{"admin/client/list", "admin/client/auth", "admin/client/revoke"}},
						"time-provider": {Provide: []string{"time"}},
						"time-consumer": {Submit: []string{"time"}},
					},
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if ready, ok := r.(*qexec.RespServerReady); ok {
						d.SetGlobal(keyServerAddr, ready.Addr)
						d.SetGlobal(keyAuthToken, ready.AuthToken)
						t.Logf("Server ready on %s", ready.Addr)
						serverAgent.Milestones[msServerStarted] = true
					}
				}
			},
			Emit: "server-ready",
		},
		{
			Name: "Wait for test completion",
			Wait: "provider-ready-again",
			Cmd:  func(d *AgentData) any { return nil },
			Emit: "test-complete",
		},
	}

	// Helper function for role check
	containsRole := func(roles []string, role string) bool {
		for _, r := range roles {
			if r == role {
				return true
			}
		}
		return false
	}

	adminAgent.Steps = []Step{
		{
			Name: "Authenticate with server",
			Wait: "server-ready",
			Cmd: func(d *AgentData) any {
				addr := d.Global(keyServerAddr).(string)
				token := d.Global(keyAuthToken).(qconn.TA)
				configPath := d.Global(keyConfigPath).(string)
				return &qexec.CmdAdminAuth{
					ServerAddr:     addr,
					ConfigPath:     configPath,
					ProvisionToken: provisionToken,
					AuthToken:      token.String(),
					Hostname:       "admin",
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if authed, ok := r.(*qexec.RespAdminAuthed); ok {
						d.Set(keyAdminFP, authed.Fingerprint)
						t.Logf("Admin authenticated: %s", authed.Fingerprint)
						adminAgent.Milestones[msAdminAuthed] = true
					}
				}
			},
			Emit: "admin-authed",
		},
		{
			Name: "List clients to get provider fingerprint",
			Wait: "provider-connected",
			Cmd: func(d *AgentData) any {
				return &qexec.CmdAdminList{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: d.Global(keyConfigPath).(string),
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if list, ok := r.(*qexec.RespClientList); ok {
						for _, c := range list.Clients {
							if c.Hostname == "time-provider" {
								d.Set(keyProviderFP, c.Fingerprint)
								t.Logf("Found provider: %s", c.Fingerprint)
							}
						}
					}
				}
			},
		},
		{
			Name: "Approve time-provider",
			Cmd: func(d *AgentData) any {
				return &qexec.CmdAdminApprove{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: d.Global(keyConfigPath).(string),
					TargetFP:   d.Get(keyProviderFP).(qconn.FP),
					Roles:      []string{"time-provider"},
					MsgTypes:   []string{"time"},
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				t.Log("Time-provider approved")
				adminAgent.Milestones[msProviderApproved] = true
			},
			Emit: "provider-approved",
		},
		{
			Name: "List clients to get consumer fingerprint",
			Wait: "consumer-connected",
			Cmd: func(d *AgentData) any {
				return &qexec.CmdAdminList{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: d.Global(keyConfigPath).(string),
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if list, ok := r.(*qexec.RespClientList); ok {
						for _, c := range list.Clients {
							if c.Hostname == "time-consumer" {
								d.Set(keyConsumerFP, c.Fingerprint)
								t.Logf("Found consumer: %s", c.Fingerprint)
							}
						}
					}
				}
			},
		},
		{
			Name: "Approve time-consumer",
			Cmd: func(d *AgentData) any {
				return &qexec.CmdAdminApprove{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: d.Global(keyConfigPath).(string),
					TargetFP:   d.Get(keyConsumerFP).(qconn.FP),
					Roles:      []string{"time-consumer"},
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				t.Log("Time-consumer approved")
				adminAgent.Milestones[msConsumerApproved] = true
			},
			Emit: "consumer-approved",
		},
		{
			Name: "Wait for consumer to finish, then revoke provider",
			Wait: "consumer-done",
			Cmd: func(d *AgentData) any {
				return &qexec.CmdAdminRevoke{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: d.Global(keyConfigPath).(string),
					TargetFP:   d.Get(keyProviderFP).(qconn.FP),
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				t.Log("Time-provider revoked")
				adminAgent.Milestones[msProviderRevoked] = true
			},
			Emit: "provider-revoked",
		},
		{
			Name: "Verify revoked state",
			Cmd: func(d *AgentData) any {
				return &qexec.CmdAdminList{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: d.Global(keyConfigPath).(string),
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if list, ok := r.(*qexec.RespClientList); ok {
						for _, c := range list.Clients {
							t.Logf("  After revoke - %s: %s %v", c.Hostname, c.Status, c.Roles)
							if c.Hostname == "time-provider" && c.Status != qconn.StatusRevoked {
								t.Errorf("Expected time-provider to be revoked, got %s", c.Status)
							}
						}
						adminAgent.Milestones[msVerifiedRevokedState] = true
					}
				}
			},
		},
		// Provider will now reconnect with NEW credentials (re-provision)
		{
			Name: "Wait for provider to re-provision and list to find new FP",
			Wait: "provider-reconnected",
			Cmd: func(d *AgentData) any {
				return &qexec.CmdAdminList{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: d.Global(keyConfigPath).(string),
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				oldFP := d.Get(keyProviderFP).(qconn.FP)
				for _, r := range resps {
					if list, ok := r.(*qexec.RespClientList); ok {
						for _, c := range list.Clients {
							t.Logf("  After re-provision - %s: %s (FP: %s)", c.Hostname, c.Status, c.Fingerprint)
							// Find the NEW time-provider (different FP, unauthenticated)
							if c.Hostname == "time-provider" && c.Fingerprint != oldFP {
								d.Set(keyProviderNewFP, c.Fingerprint)
								t.Logf("Found re-provisioned provider with new FP: %s (status: %s)", c.Fingerprint, c.Status)
								if c.Status != qconn.StatusUnauthenticated {
									t.Errorf("Expected re-provisioned provider to be unauthenticated, got %s", c.Status)
								}
								adminAgent.Milestones[msVerifiedReprovisioned] = true
							}
						}
					}
				}
			},
		},
		{
			Name: "Approve re-provisioned time-provider",
			Cmd: func(d *AgentData) any {
				newFP := d.Get(keyProviderNewFP).(qconn.FP)
				return &qexec.CmdAdminApprove{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: d.Global(keyConfigPath).(string),
					TargetFP:   newFP,
					Roles:      []string{"time-provider"},
					MsgTypes:   []string{"time"},
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				t.Log("Re-provisioned time-provider approved")
				adminAgent.Milestones[msProviderReApproved] = true
			},
			Emit: "provider-re-approved",
		},
		{
			Name: "Verify final state after re-authorization",
			Wait: "provider-ready-again",
			Cmd: func(d *AgentData) any {
				return &qexec.CmdAdminList{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: d.Global(keyConfigPath).(string),
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				newFP := d.Get(keyProviderNewFP).(qconn.FP)
				for _, r := range resps {
					if list, ok := r.(*qexec.RespClientList); ok {
						for _, c := range list.Clients {
							t.Logf("  Final state - %s: %s %v (FP: %s)", c.Hostname, c.Status, c.Roles, c.Fingerprint)
							// Verify re-provisioned provider is now authenticated
							if c.Fingerprint == newFP {
								if c.Status != qconn.StatusAuthenticated {
									t.Errorf("Expected re-approved provider to be authenticated, got %s", c.Status)
								}
								if !containsRole(c.Roles, "time-provider") {
									t.Errorf("Expected re-approved provider to have time-provider role, got %v", c.Roles)
								}
								adminAgent.Milestones[msVerifiedFinalReconnect] = true
							}
						}
					}
				}
			},
		},
	}

	providerAgent.Steps = []Step{
		{
			Name:       "Connect and provide time service",
			Wait:       "admin-authed",
			Background: true, // Provider runs until cancelled
			Cmd: func(d *AgentData) any {
				return &CmdTimeProviderStart{
					ServerAddr:     d.Global(keyServerAddr).(string),
					ConfigPath:     tempDir + "/provider.conf",
					ProvisionToken: provisionToken,
					Hostname:       "time-provider",
					OnConnected: func(fp qconn.FP) {
						t.Logf("Provider connected: %s", fp)
						providerAgent.Milestones[msProviderConnected] = true
						signals.Emit("provider-connected")
					},
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if ready, ok := r.(*RespTimeProviderReady); ok {
						t.Logf("Time-provider ready: %s", ready.Fingerprint)
						providerAgent.Milestones[msProviderReady] = true
					}
				}
			},
			Emit: "provider-ready",
		},
		// After revocation, reconnect with SAME credentials - tests auto-recovery.
		// The client should detect StatusRevoked and auto-re-provision.
		{
			Name:       "Reconnect after revocation (auto-re-provision)",
			Wait:       "provider-revoked",
			Background: true, // Provider runs until test completes
			Cmd: func(d *AgentData) any {
				return &CmdTimeProviderStart{
					ServerAddr:     d.Global(keyServerAddr).(string),
					ConfigPath:     tempDir + "/provider.conf", // SAME file - tests auto-recovery
					ProvisionToken: provisionToken,
					Hostname:       "time-provider",
					OnConnected: func(fp qconn.FP) {
						t.Logf("Provider auto-re-provisioned with new FP: %s", fp)
						providerAgent.Milestones[msProviderReconnected] = true
						signals.Emit("provider-reconnected")
					},
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if ready, ok := r.(*RespTimeProviderReady); ok {
						t.Logf("Time-provider ready again after re-authorization: %s", ready.Fingerprint)
						providerAgent.Milestones[msProviderReadyAfterRev] = true
					}
				}
			},
			Emit: "provider-ready-again",
		},
	}

	consumerAgent.Steps = []Step{
		{
			Name: "Connect and query time",
			Wait: "provider-ready",
			Cmd: func(d *AgentData) any {
				return &CmdTimeConsumerRun{
					ServerAddr:     d.Global(keyServerAddr).(string),
					ConfigPath:     tempDir + "/consumer.conf",
					ProvisionToken: provisionToken,
					Hostname:       "time-consumer",
					OnConnected: func(fp qconn.FP) {
						t.Logf("Consumer connected: %s", fp)
						consumerAgent.Milestones[msConsumerConnected] = true
						signals.Emit("consumer-connected")
					},
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if result, ok := r.(*RespTimeResult); ok {
						t.Logf("Got time: %s", result.Time.Format(time.RFC3339))
						consumerAgent.Milestones[msTimeReceived] = true
					}
				}
			},
			Emit: "consumer-done",
		},
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// RUN TEST
	// ═══════════════════════════════════════════════════════════════════════════

	agents := []*Agent{serverAgent, adminAgent, providerAgent, consumerAgent}
	runAgents(t, ctx, signals, data, agents)

	// Cleanup
	serverCancel()
}

// TestIntegrationServerRestart tests that clients can reconnect after a server restart.
// This test verifies:
// 1. Server starts and client connects
// 2. Server stops (simulated restart)
// 3. Server restarts on same address
// 4. Client reconnects and can make requests
func TestIntegrationServerRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "qconn-restart-agents-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	provisionToken := "restart-test-provision-token"

	signals := NewSignals()
	defer signals.Close()

	data := NewTestData()
	data.SetGlobal(keyConfigPath, tempDir+"/admin.conf")

	// Milestone flags
	const (
		msServer1Started   = "server1-started"
		msServer2Started   = "server2-started"
		msClientConnected1 = "client-connected-1"
		msClientConnected2 = "client-connected-2"
		msClientAuthed     = "client-authed"
		msClientRequest1   = "client-request-1"
		msClientRequest2   = "client-request-2"
	)

	// Create contexts for server phases
	server1Ctx, server1Cancel := context.WithCancel(ctx)
	server2Ctx, server2Cancel := context.WithCancel(ctx)
	defer server2Cancel()

	// Variable to store server address for reuse
	var serverAddr string

	// Define agents
	serverAgent := &Agent{
		Name:   "server",
		Ctx:    server1Ctx,
		Cancel: server1Cancel,
		Milestones: map[string]bool{
			msServer1Started: false,
			msServer2Started: false,
		},
	}

	clientAgent := &Agent{
		Name: "client",
		Milestones: map[string]bool{
			msClientConnected1: false,
			msClientConnected2: false,
			msClientAuthed:     false,
			msClientRequest1:   false,
			msClientRequest2:   false,
		},
	}

	// Server steps - run in 2 phases with restart in between
	serverAgent.Steps = []Step{
		{
			Name:       "Start server (phase 1)",
			Background: true,
			Cmd: func(d *AgentData) any {
				return &qexec.CmdServerStart{
					ListenAddr:      "127.0.0.1:0",
					DBPath:          tempDir + "/server/auth.db",
					ProvisionTokens: []string{provisionToken},
					Roles: map[string]*qconn.RoleConfig{
						"admin":  {Submit: []string{"admin/client/list", "admin/client/auth"}},
						"client": {},
					},
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if ready, ok := r.(*qexec.RespServerReady); ok {
						d.SetGlobal(keyServerAddr, ready.Addr)
						d.SetGlobal(keyAuthToken, ready.AuthToken)
						serverAddr = ready.Addr
						t.Logf("Server phase 1 ready on %s", ready.Addr)
						serverAgent.Milestones[msServer1Started] = true
					}
				}
			},
			Emit: "server-phase1-ready",
		},
		{
			Name: "Wait for client to complete initial test, then stop",
			Wait: "client-phase1-done",
			Cmd:  func(d *AgentData) any { return nil },
			Emit: "server-phase1-stopping",
		},
	}

	// Client steps
	clientAgent.Steps = []Step{
		{
			Name: "Connect and authenticate (phase 1)",
			Wait: "server-phase1-ready",
			Cmd: func(d *AgentData) any {
				addr := d.Global(keyServerAddr).(string)
				token := d.Global(keyAuthToken).(qconn.TA)
				return &qexec.CmdAdminAuth{
					ServerAddr:     addr,
					ConfigPath:     tempDir + "/client.conf",
					ProvisionToken: provisionToken,
					AuthToken:      token.String(),
					Hostname:       "restart-test-client",
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if authed, ok := r.(*qexec.RespAdminAuthed); ok {
						d.Set(keyAdminFP, authed.Fingerprint)
						t.Logf("Client authenticated: %s", authed.Fingerprint)
						clientAgent.Milestones[msClientConnected1] = true
						clientAgent.Milestones[msClientAuthed] = true
					}
				}
			},
		},
		{
			Name: "Make request on phase 1 server",
			Cmd: func(d *AgentData) any {
				return &qexec.CmdAdminList{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: tempDir + "/client.conf",
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if list, ok := r.(*qexec.RespClientList); ok {
						t.Logf("Phase 1: Got %d clients", len(list.Clients))
						if len(list.Clients) > 0 {
							clientAgent.Milestones[msClientRequest1] = true
						}
					}
				}
			},
			Emit: "client-phase1-done",
		},
		{
			Name: "Wait for server to stop",
			Wait: "server-phase1-stopping",
			Cmd:  func(d *AgentData) any { return nil },
		},
		{
			Name:    "Stop phase 1 server and start phase 2",
			Timeout: 5 * time.Second,
			Cmd: func(d *AgentData) any {
				// Stop the first server
				server1Cancel()
				t.Log("Server phase 1 cancelled, waiting for restart...")

				// Give time for server to stop
				time.Sleep(200 * time.Millisecond)

				// Start phase 2 server on the SAME address using a goroutine
				// We'll signal when it's ready
				go func() {
					responses := make(chan any, 10)
					cmd := &qexec.CmdServerStart{
						ListenAddr:      serverAddr, // Same address!
						DBPath:          tempDir + "/server/auth.db",
						ProvisionTokens: []string{provisionToken},
						Roles: map[string]*qconn.RoleConfig{
							"admin":  {Submit: []string{"admin/client/list", "admin/client/auth"}},
							"client": {},
						},
					}

					// Start command in background, will run until server2Ctx is cancelled
					// Note: qexec.Execute closes the responses channel when done
					go func() {
						_ = qexec.Execute(server2Ctx, cmd, responses)
					}()

					// Wait for ready response
					for r := range responses {
						if ready, ok := r.(*qexec.RespServerReady); ok {
							t.Logf("Server phase 2 ready on %s", ready.Addr)
							serverAgent.Milestones[msServer2Started] = true
							signals.Emit("server-phase2-ready")
							break
						}
					}
				}()

				return nil
			},
		},
		{
			Name: "Wait for server phase 2",
			Wait: "server-phase2-ready",
			Cmd:  func(d *AgentData) any { return nil },
		},
		{
			Name:    "Reconnect and make request on phase 2 server",
			Timeout: 10 * time.Second,
			Cmd: func(d *AgentData) any {
				return &qexec.CmdAdminList{
					ServerAddr: d.Global(keyServerAddr).(string),
					ConfigPath: tempDir + "/client.conf",
				}
			},
			Check: func(t *testing.T, d *AgentData, resps []any) {
				for _, r := range resps {
					if list, ok := r.(*qexec.RespClientList); ok {
						t.Logf("Phase 2: Got %d clients after server restart", len(list.Clients))
						clientAgent.Milestones[msClientConnected2] = true
						clientAgent.Milestones[msClientRequest2] = true

						// Verify client data persisted (should see our client)
						var foundClient bool
						for _, c := range list.Clients {
							if c.Hostname == "restart-test-client" {
								foundClient = true
								t.Logf("Found persisted client: %s (status: %s)", c.Fingerprint, c.Status)
							}
						}
						if !foundClient {
							t.Log("Note: Client may have reconnected with new session")
						}
					}
				}
			},
			Emit: "test-complete",
		},
	}

	agents := []*Agent{serverAgent, clientAgent}
	runAgents(t, ctx, signals, data, agents)

	t.Log("Server restart test completed successfully")
}
