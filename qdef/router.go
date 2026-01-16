package qdef

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

type HandleFunc[Req, Resp any] func(ctx context.Context, id Identity, req *Req) (*Resp, error)

type serviceKey struct {
	service ServiceType
	name    string
}

type genericHandler struct {
	reqType  reflect.Type
	respType reflect.Type
	fn       reflect.Value
}

// StreamRouter manages the registration and dispatching of handlers.
type StreamRouter struct {
	mu       sync.RWMutex
	handlers map[serviceKey]genericHandler
}

// Handle registers a handler for a given service and type.
func Handle[Req, Resp any](r *StreamRouter, service ServiceType, name string, h HandleFunc[Req, Resp]) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handlers == nil {
		r.handlers = make(map[serviceKey]genericHandler)
	}

	key := serviceKey{service: service, name: name}
	r.handlers[key] = genericHandler{
		reqType:  reflect.TypeOf((*Req)(nil)).Elem(),
		respType: reflect.TypeOf((*Resp)(nil)).Elem(),
		fn:       reflect.ValueOf(h),
	}
}

// ErrNoHandler is returned when no handler is registered for the target service/type.
var ErrNoHandler = fmt.Errorf("qconn: no handler for target")

// NoHandlerError provides details about which handler was not found.
type NoHandlerError struct {
	Service ServiceType
	Type    string
}

func (e NoHandlerError) Error() string {
	return fmt.Sprintf("%s: %s/%s", ErrNoHandler, e.Service, e.Type)
}

func (e NoHandlerError) Unwrap() error {
	return ErrNoHandler
}

// Dispatch decodes a message payload, calls the appropriate handler, and returns
// the response. The caller is responsible for encoding the response to the stream.
// Returns (response, nil) on success, (nil, NoHandlerError) if no handler is registered,
// or (nil, error) if processing fails.
func (r *StreamRouter) Dispatch(ctx context.Context, id Identity, msg Message) (any, error) {
	r.mu.RLock()
	handler, ok := r.handlers[serviceKey{service: msg.Target.Service, name: msg.Target.Type}]
	r.mu.RUnlock()
	if !ok {
		return nil, NoHandlerError{Service: msg.Target.Service, Type: msg.Target.Type}
	}

	// Use reflection to call the handler.
	reqPtr := reflect.New(handler.reqType)
	if err := cbor.Unmarshal(msg.Payload, reqPtr.Interface()); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	results := handler.fn.Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(id),
		reqPtr,
	})

	respErr := results[1].Interface()
	if respErr != nil {
		return nil, respErr.(error)
	}

	return results[0].Interface(), nil
}
