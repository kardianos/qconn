package qmanage

import "time"

// timeNow returns the current time. It can be overridden in tests
// to simulate time passing for certificate expiry testing.
var timeNow = time.Now
