package qconn

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
)

func BenchmarkClientRouting(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	auth := newMockAuthManager(&testing.T{})

	// Create server.
	server, err := NewServer(ServerOpt{
		Auth:    auth,
		Clients: auth,
	})
	if err != nil {
		b.Fatal(err)
	}

	// Start server.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		if err := server.Serve(ctx, conn); err != nil {
			b.Error(err)
		}
	}()

	serverAddr := conn.LocalAddr().String()

	// Create client A.
	authA, err := auth.clientAuth("client-a")
	if err != nil {
		b.Fatal(err)
	}
	clientA, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       authA,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = clientA.Close() }()

	// Create client B with echo handler.
	authB, err := auth.clientAuth("client-b")
	if err != nil {
		b.Fatal(err)
	}

	echoHandler := func(ctx context.Context, msg *Message, w io.Writer, ack Ack) error {
		_, err := w.Write(msg.Payload)
		return err
	}

	clientB, err := NewClient(ctx, ClientOpt{
		ServerAddr: serverAddr,
		Auth:       authB,
		Handler:    echoHandler,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = clientB.Close() }()

	// Ensure client B is connected.
	var clients []*ClientRecord
	if err := clientB.Request(ctx, System(), "admin/client/list", "", nil, &clients); err != nil {
		b.Fatal(err)
	}

	type testPayload struct {
		Data []byte `cbor:"data"`
	}
	payload := testPayload{Data: make([]byte, 64)}

	b.Run("SingleSender", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			var resp testPayload
			if err := clientA.Request(ctx, ToMachine("client-b"), "echo", "", &payload, &resp); err != nil {
				b.Fatal(err)
			}
		}
	})

	// For bidirectional test, client A also needs a handler.
	// Create fresh clients with handlers on both sides.
	b.Run("BidirectionalSenders", func(b *testing.B) {
		// Create client C (sender/receiver).
		authC, err := auth.clientAuth("client-c")
		if err != nil {
			b.Fatal(err)
		}

		clientC, err := NewClient(ctx, ClientOpt{
			ServerAddr: serverAddr,
			Auth:       authC,
			Handler:    echoHandler,
		})
		if err != nil {
			b.Fatal(err)
		}
		defer func() { _ = clientC.Close() }()

		// Create client D (sender/receiver).
		authD, err := auth.clientAuth("client-d")
		if err != nil {
			b.Fatal(err)
		}

		clientD, err := NewClient(ctx, ClientOpt{
			ServerAddr: serverAddr,
			Auth:       authD,
			Handler:    echoHandler,
		})
		if err != nil {
			b.Fatal(err)
		}
		defer func() { _ = clientD.Close() }()

		// Ensure both are connected.
		if err := clientC.Request(ctx, System(), "admin/client/list", "", nil, &clients); err != nil {
			b.Fatal(err)
		}
		if err := clientD.Request(ctx, System(), "admin/client/list", "", nil, &clients); err != nil {
			b.Fatal(err)
		}

		b.ReportAllocs()
		b.ResetTimer()

		var wg sync.WaitGroup
		wg.Add(2)

		// Client C sends b.N messages to D.
		go func() {
			defer wg.Done()
			for i := 0; i < b.N; i++ {
				var resp testPayload
				if err := clientC.Request(ctx, ToMachine("client-d"), "echo", "", &payload, &resp); err != nil {
					b.Error(err)
					return
				}
			}
		}()

		// Client D sends b.N messages to C.
		go func() {
			defer wg.Done()
			for i := 0; i < b.N; i++ {
				var resp testPayload
				if err := clientD.Request(ctx, ToMachine("client-c"), "echo", "", &payload, &resp); err != nil {
					b.Error(err)
					return
				}
			}
		}()

		wg.Wait()
	})
}
