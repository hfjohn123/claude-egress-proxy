package timebase

import "time"

// Real is the production Clock backed by the standard library.
type Real struct{}

func (Real) Now() time.Time { return time.Now() }

func (Real) NewTimer(duration time.Duration) Timer {
	return realTimer{timer: time.NewTimer(duration)}
}

func (Real) NewTicker(duration time.Duration) Ticker {
	return realTicker{ticker: time.NewTicker(duration)}
}

type realTimer struct{ timer *time.Timer }

func (t realTimer) C() <-chan time.Time               { return t.timer.C }
func (t realTimer) Stop() bool                        { return t.timer.Stop() }
func (t realTimer) Reset(duration time.Duration) bool { return t.timer.Reset(duration) }

type realTicker struct{ ticker *time.Ticker }

func (t realTicker) C() <-chan time.Time { return t.ticker.C }
func (t realTicker) Stop()               { t.ticker.Stop() }
