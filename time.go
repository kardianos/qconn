package qconn

import (
	"sync"
	"time"
)

// timeMu protects fakeTime for concurrent access.
var timeMu sync.RWMutex

// fakeTime is the fake time to return from timeNow, or nil to use real time.
var fakeTime *time.Time

// timeNow returns the current time. In tests, use setFakeTime to override.
func timeNow() time.Time {
	timeMu.RLock()
	defer timeMu.RUnlock()
	if fakeTime != nil {
		return *fakeTime
	}
	return time.Now()
}

// setFakeTime sets a fake time for testing. Pass nil to reset to real time.
// Returns a cleanup function that restores real time.
func setFakeTime(t *time.Time) func() {
	timeMu.Lock()
	defer timeMu.Unlock()
	fakeTime = t
	return func() {
		timeMu.Lock()
		defer timeMu.Unlock()
		fakeTime = nil
	}
}

// advanceFakeTime advances the fake time by the given duration.
// Panics if fake time is not set.
func advanceFakeTime(d time.Duration) {
	timeMu.Lock()
	defer timeMu.Unlock()
	if fakeTime == nil {
		panic("advanceFakeTime called without setFakeTime")
	}
	newTime := fakeTime.Add(d)
	fakeTime = &newTime
}
