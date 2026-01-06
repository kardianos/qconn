package qconn

import (
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestTagged(t *testing.T) {
	// Define types (no special tags needed on structs)
	type MessageA struct {
		Field string
	}
	type MessageB struct {
		Property int64
	}

	var em cbor.EncMode
	var dm cbor.DecMode
	tags := cbor.NewTagSet()
	tags.Add(cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(MessageA{}), 100_001) // Custom tag > 23 to avoid conflicts
	tags.Add(cbor.TagOptions{EncTag: cbor.EncTagRequired, DecTag: cbor.DecTagRequired},
		reflect.TypeOf(MessageB{}), 100_002)
	var err error
	em, err = cbor.EncOptions{}.EncModeWithTags(tags) // Or CoreDetEncOptions for determinism
	if err != nil {
		t.Fatal(err)
	}
	dm, err = cbor.DecOptions{}.DecModeWithTags(tags)
	if err != nil {
		t.Fatal(err)
	}

	// Encode: Library adds tag based on type
	const wantMessage = "hello"
	msg := MessageA{Field: wantMessage}
	data, err := em.Marshal(msg) // Produces tagged CBOR: tag 100 + map for MessageA

	// Decode to interface{} and type-assert
	var gotMessageA bool
	var v interface{}
	err = dm.Unmarshal(data, &v)
	switch msg := v.(type) {
	case MessageA:
		gotMessageA = true
		if msg.Field != wantMessage {
			t.Errorf("incorrect field text %q", msg.Field)
		}
	case MessageB:
		// Handle MessageB
	}
	if !gotMessageA {
		t.Error("failed to get MessageA")
	}
}
