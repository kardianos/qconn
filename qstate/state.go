// Package qstate provides explicit state machine management for qconn
// client and server connection lifecycles.
package qstate

import (
	"fmt"
	"sync"
)

type State interface {
	comparable
	fmt.Stringer
}

// Transition defines a valid state transition.
type Transition[S State] struct {
	From S
	To   S
	Name string // Human-readable name for logging/debugging
}

type transitionKey[S State] struct {
	From, To S
}

// Machine enforces valid state transitions.
type Machine[S State] struct {
	mu      sync.RWMutex
	current S

	allowed  map[transitionKey[S]]string
	onChange func(from, to S, name string)
}

// New creates a state machine starting at the given state.
func New[S State](initial S, transitions []Transition[S], on func(from, to S, name string)) *Machine[S] {
	sm := &Machine[S]{
		current:  initial,
		allowed:  make(map[transitionKey[S]]string),
		onChange: on,
	}
	for _, t := range transitions {
		sm.allowed[transitionKey[S]{From: t.From, To: t.To}] = t.Name
	}
	return sm
}

func (sm *Machine[S]) look(from, to S) (string, bool) {
	name, ok := sm.allowed[transitionKey[S]{From: from, To: to}]
	return name, ok
}

// CanTransitionTo checks if a transition to the target state is valid.
func (sm *Machine[S]) CanTransitionTo(to S) bool {
	sm.mu.RLock()
	c := sm.current
	sm.mu.RUnlock()

	_, ok := sm.look(c, to)
	return ok
}

// TransitionTo attempts to transition to a new state.
// Returns an error if the transition is invalid.
func (sm *Machine[S]) TransitionTo(to S) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	c := sm.current

	name, ok := sm.look(c, to)
	if !ok {
		fromName := c.String()
		toName := to.String()
		return fmt.Errorf("invalid state transition: %s -> %s", fromName, toName)
	}
	sm.current = to
	if sm.onChange != nil {
		sm.onChange(c, to, name)
	}
	return nil
}

// MustTransitionTo transitions or panics. Use in cases where invalid
// transitions indicate a programming error.
func (sm *Machine[S]) MustTransitionTo(to S) {
	if err := sm.TransitionTo(to); err != nil {
		panic(err)
	}
}

// Current returns the current state.
func (sm *Machine[S]) Current() S {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.current
}
