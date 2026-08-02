// Package timebase provides the injected clocks used by runtime deadlines and pollers.
package timebase

import "time"

// Clock supplies runtime time without coupling callers to ambient package time.
type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
	NewTicker(time.Duration) Ticker
}

// Timer is the timer behavior used by deadlines.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(time.Duration) bool
}

// Ticker is the ticker behavior used by pollers.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}
