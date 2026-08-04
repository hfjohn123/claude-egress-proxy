package telemetry

import (
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

func TestPrivateRegistry(t *testing.T) {
	m, err := NewMetrics(timebase.Real{}, func() (time.Time, bool) { return time.Now().Add(time.Hour), true })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Gatherer().Gather(); err != nil {
		t.Fatal(err)
	}
}
