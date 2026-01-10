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

// Dispatch decodes a message and calls the appropriate handler.
// Returns nil on success, ErrNoHandler if no handler is registered,
// or another error if processing fails.
func (r *StreamRouter) Dispatch(ctx context.Context, id Identity, msg Message, stream Stream) error {
	r.mu.RLock()
	handler, ok := r.handlers[serviceKey{service: msg.Target.Service, name: msg.Target.Type}]
	r.mu.RUnlock()
	if !ok {
		return NoHandlerError{Service: msg.Target.Service, Type: msg.Target.Type}
	}
	defer func() { _ = stream.Close() }()

	var dispatchErr error

	// Helper to send error response. Records encoding errors.
	sendError := func(errMsg string) {
		resp := Message{
			ID:    msg.ID,
			Error: errMsg,
		}
		if err := cbor.NewEncoder(stream).Encode(resp); err != nil {
			dispatchErr = fmt.Errorf("failed to encode error response: %w", err)
		}
	}

	// Recover from panics in handlers to prevent connection corruption.
	defer func() {
		if p := recover(); p != nil {
			dispatchErr = fmt.Errorf("handler panic in %s/%s: %v", msg.Target.Service, msg.Target.Type, p)
			sendError("internal server error")
		}
	}()

	// Use reflection to call the handler.
	reqPtr := reflect.New(handler.reqType)
	if err := cbor.Unmarshal(msg.Payload, reqPtr.Interface()); err != nil {
		sendError(fmt.Sprintf("failed to unmarshal request: %v", err))
		return dispatchErr
	}

	results := handler.fn.Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(id),
		reqPtr,
	})

	respErr := results[1].Interface()
	if respErr != nil {
		sendError(respErr.(error).Error())
		return dispatchErr
	}

	rawResp, err := cbor.Marshal(results[0].Interface())
	if err != nil {
		sendError(fmt.Sprintf("failed to marshal response: %v", err))
		return dispatchErr
	}

	resp := Message{
		ID:      msg.ID,
		Payload: rawResp,
	}
	if err := cbor.NewEncoder(stream).Encode(resp); err != nil {
		return fmt.Errorf("failed to encode response: %w", err)
	}
	return dispatchErr
}
