package proxy

import (
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

type connectClock struct{ now time.Time }

func (c connectClock) Now() time.Time                        { return c.now }
func (connectClock) NewTimer(time.Duration) timebase.Timer   { panic("unused") }
func (connectClock) NewTicker(time.Duration) timebase.Ticker { panic("unused") }

func TestPublicConfigUsesSuppliedClock(t *testing.T) {
	want := time.Unix(123, 0)
	if got := publicNow(PublicConfig{Clock: connectClock{now: want}}); !got.Equal(want) {
		t.Fatalf("now=%v want=%v", got, want)
	}
}
