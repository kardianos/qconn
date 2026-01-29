package qconn

import (
	"sync"
	"time"
)

// timeMu protects fakeTime for concurrent access.
var timeMu sync.RWMutex

// fakeTime is the fake time to return from timeNow, or nil to use real time.
var fakeTime *time.Time

func init() {
	// Replace timeNow with a mutex-protected version for tests.
	timeNow = func() time.Time {
		timeMu.RLock()
		defer timeMu.RUnlock()
		if fakeTime != nil {
			return *fakeTime
		}
		return time.Now()
	}
}

// resetFakeTime ensures fake time is cleared. Call at start of tests that don't use fake time
// but might be affected by previous tests that didn't clean up properly.
func resetFakeTime() {
	timeMu.Lock()
	fakeTime = nil
	timeMu.Unlock()
}

// setFakeTime sets a fake time for testing.
// Returns a cleanup function that restores real time.
// A test can call setFakeTime multiple times to update the value.
// Only the cleanup from the FIRST call should be used (via defer).
func setFakeTime(t *time.Time) func() {
	timeMu.Lock()
	fakeTime = t
	timeMu.Unlock()

	return func() {
		timeMu.Lock()
		fakeTime = nil
		timeMu.Unlock()
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
