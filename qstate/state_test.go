package qstate

import (
	"testing"
)

// testState is a simple state type for testing.
type testState int

const (
	stateNew testState = iota
	stateConnecting
	stateConnected
	stateDisconnected
)

func (s testState) String() string {
	switch s {
	case stateNew:
		return "new"
	case stateConnecting:
		return "connecting"
	case stateConnected:
		return "connected"
	case stateDisconnected:
		return "disconnected"
	default:
		return "unknown"
	}
}

func TestStateMachine(t *testing.T) {
	transitions := []Transition[testState]{
		{From: stateNew, To: stateConnecting, Name: "start"},
		{From: stateConnecting, To: stateConnected, Name: "connected"},
		{From: stateConnecting, To: stateDisconnected, Name: "failed"},
		{From: stateConnected, To: stateDisconnected, Name: "disconnect"},
	}

	tests := []struct {
		name        string
		initial     testState
		transition  testState
		wantErr     bool
		wantCanMove bool
	}{
		{
			name:        "valid: new -> connecting",
			initial:     stateNew,
			transition:  stateConnecting,
			wantErr:     false,
			wantCanMove: true,
		},
		{
			name:        "valid: connecting -> connected",
			initial:     stateConnecting,
			transition:  stateConnected,
			wantErr:     false,
			wantCanMove: true,
		},
		{
			name:        "valid: connecting -> disconnected",
			initial:     stateConnecting,
			transition:  stateDisconnected,
			wantErr:     false,
			wantCanMove: true,
		},
		{
			name:        "valid: connected -> disconnected",
			initial:     stateConnected,
			transition:  stateDisconnected,
			wantErr:     false,
			wantCanMove: true,
		},
		{
			name:        "invalid: new -> connected (skip connecting)",
			initial:     stateNew,
			transition:  stateConnected,
			wantErr:     true,
			wantCanMove: false,
		},
		{
			name:        "invalid: new -> disconnected",
			initial:     stateNew,
			transition:  stateDisconnected,
			wantErr:     true,
			wantCanMove: false,
		},
		{
			name:        "invalid: connected -> connecting (backwards)",
			initial:     stateConnected,
			transition:  stateConnecting,
			wantErr:     true,
			wantCanMove: false,
		},
		{
			name:        "invalid: disconnected -> connected (no path)",
			initial:     stateDisconnected,
			transition:  stateConnected,
			wantErr:     true,
			wantCanMove: false,
		},
		{
			name:        "invalid: same state (new -> new)",
			initial:     stateNew,
			transition:  stateNew,
			wantErr:     true,
			wantCanMove: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := New(tt.initial, transitions, nil)

			// Test CanTransitionTo.
			canMove := sm.CanTransitionTo(tt.transition)
			if canMove != tt.wantCanMove {
				t.Errorf("CanTransitionTo() = %v, want %v", canMove, tt.wantCanMove)
			}

			// Test TransitionTo.
			err := sm.TransitionTo(tt.transition)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransitionTo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOnChangeCallback(t *testing.T) {
	transitions := []Transition[testState]{
		{From: stateNew, To: stateConnecting, Name: "start"},
		{From: stateConnecting, To: stateConnected, Name: "connected"},
	}

	var callCount int
	var lastFrom, lastTo testState
	var lastName string

	sm := New(stateNew, transitions, func(from, to testState, name string) {
		callCount++
		lastFrom = from
		lastTo = to
		lastName = name
	})

	// First transition.
	if err := sm.TransitionTo(stateConnecting); err != nil {
		t.Fatalf("TransitionTo(connecting): %v", err)
	}
	if callCount != 1 {
		t.Errorf("callback count = %d, want 1", callCount)
	}
	if lastFrom != stateNew || lastTo != stateConnecting || lastName != "start" {
		t.Errorf("callback args = (%v, %v, %q), want (new, connecting, start)", lastFrom, lastTo, lastName)
	}

	// Second transition.
	if err := sm.TransitionTo(stateConnected); err != nil {
		t.Fatalf("TransitionTo(connected): %v", err)
	}
	if callCount != 2 {
		t.Errorf("callback count = %d, want 2", callCount)
	}
	if lastFrom != stateConnecting || lastTo != stateConnected || lastName != "connected" {
		t.Errorf("callback args = (%v, %v, %q), want (connecting, connected, connected)", lastFrom, lastTo, lastName)
	}

	// Invalid transition should not call callback.
	_ = sm.TransitionTo(stateNew)
	if callCount != 2 {
		t.Errorf("callback called on invalid transition, count = %d", callCount)
	}
}
