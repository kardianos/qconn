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

// Dispatch decodes a message and calls the appropriate handler.
// It returns true if a handler was found and executed.
func (r *StreamRouter) Dispatch(ctx context.Context, id Identity, msg Message, stream Stream) bool {
	r.mu.RLock()
	handler, ok := r.handlers[serviceKey{service: msg.Target.Service, name: msg.Target.Type}]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	defer stream.Close()

	// Use reflection to call the handler.
	reqPtr := reflect.New(handler.reqType)
	if err := cbor.Unmarshal(msg.Payload, reqPtr.Interface()); err != nil {
		resp := Message{
			ID:    msg.ID,
			Error: fmt.Sprintf("failed to unmarshal request: %v", err),
		}
		cbor.NewEncoder(stream).Encode(resp)
		return true
	}

	results := handler.fn.Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(id),
		reqPtr,
	})

	respErr := results[1].Interface()
	if respErr != nil {
		resp := Message{
			ID:    msg.ID,
			Error: respErr.(error).Error(),
		}
		cbor.NewEncoder(stream).Encode(resp)
		return true
	}

	rawResp, err := cbor.Marshal(results[0].Interface())
	if err != nil {
		resp := Message{
			ID:    msg.ID,
			Error: fmt.Sprintf("failed to marshal response: %v", err),
		}
		cbor.NewEncoder(stream).Encode(resp)
		return true
	}

	resp := Message{
		ID:      msg.ID,
		Payload: rawResp,
	}
	cbor.NewEncoder(stream).Encode(resp)
	return true
}
