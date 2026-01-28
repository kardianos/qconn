package main

import (
	"time"

	"github.com/kardianos/qconn"
)

// TimeRequest is sent to request the current time.
type TimeRequest struct{}

func (TimeRequest) Type() string { return "time" }

// TimeResponse is returned by the time endpoint.
type TimeResponse struct {
	Time   time.Time `cbor:"time"`
	Format string    `cbor:"format"`
}

// RespTimeProviderReady indicates the time-provider is ready to serve requests.
type RespTimeProviderReady struct {
	Fingerprint qconn.FP
	Client      *qconn.Client // The connected client (for testing)
}

// RespTimeResult contains the result of a time query.
type RespTimeResult struct {
	Time time.Time
}
