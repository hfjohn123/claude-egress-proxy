package timebase_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

func TestRealClockSatisfiesInterfaces(t *testing.T) {
	var _ timebase.Clock = timebase.Real{}
	var _ timebase.Timer = timebase.Real{}.NewTimer(time.Second)
	var _ timebase.Ticker = timebase.Real{}.NewTicker(time.Second)
}

func TestProductionUsesNoAmbientClock(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	internal := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	forbidden := regexp.MustCompile(`\btime\.(Now|After|NewTimer|NewTicker)\(`)

	realClock := filepath.Join(internal, "timebase", "real.go")
	err := filepath.WalkDir(internal, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == realClock {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if forbidden.Match(contents) {
			t.Errorf("ambient clock call in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
