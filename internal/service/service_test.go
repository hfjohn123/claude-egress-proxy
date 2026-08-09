package service

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExecuteDispatchesSelectedActionWithCanonicalConfig(t *testing.T) {
	configPath := testConfigPath(t)
	platform := &recordingPlatform{}
	for _, action := range []Action{Install, Uninstall, Start, Stop} {
		t.Run(action.String(), func(t *testing.T) {
			if err := Execute(context.Background(), platform, action, configPath); err != nil {
				t.Fatal(err)
			}
			if got := platform.calls[len(platform.calls)-1]; got.action != action || got.configPath != configPath {
				t.Fatalf("call = %+v, want action %v config %q", got, action, configPath)
			}
		})
	}
}

func TestExecuteRejectsNonCanonicalPathBeforePlatformMutation(t *testing.T) {
	platform := &recordingPlatform{}
	path := filepath.Dir(testConfigPath(t)) + string(filepath.Separator) + ".." + string(filepath.Separator) + "config.yaml"
	if err := Execute(context.Background(), platform, Install, path); !errors.Is(err, ErrInvalidConfigPath) {
		t.Fatalf("Execute error = %v, want ErrInvalidConfigPath", err)
	}
	if len(platform.calls) != 0 {
		t.Fatalf("platform calls = %d, want 0", len(platform.calls))
	}
}

func TestTransactionRollsBackCompletedStepsInReverseOrder(t *testing.T) {
	var order []string
	err := RunTransaction(context.Background(), []Step{
		func(context.Context) (Undo, error) {
			order = append(order, "one")
			return func(context.Context) error { order = append(order, "undo-one"); return nil }, nil
		},
		func(context.Context) (Undo, error) {
			order = append(order, "two")
			return func(context.Context) error { order = append(order, "undo-two"); return nil }, nil
		},
		func(context.Context) (Undo, error) { order = append(order, "three"); return nil, errors.New("stop") },
	})
	if err == nil {
		t.Fatal("RunTransaction succeeded")
	}
	want := []string{"one", "two", "three", "undo-two", "undo-one"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

type serviceCall struct {
	action     Action
	configPath string
}

type recordingPlatform struct{ calls []serviceCall }

func (p *recordingPlatform) Apply(_ context.Context, action Action, configPath string) error {
	p.calls = append(p.calls, serviceCall{action: action, configPath: configPath})
	return nil
}

func testConfigPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\ClaudeEgressProxy\config.yaml`
	}
	return "/etc/claude-egress-proxy/config.yaml"
}
