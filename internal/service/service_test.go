package service

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExecuteDispatchesSelectedActionWithCanonicalConfig(t *testing.T) {
	platform := &recordingPlatform{}
	selection := Selection{ConfigPath: testConfigPath(t), StateRoot: testStatePath(t)}
	for _, action := range []Action{Install, Uninstall, Start, Stop} {
		t.Run(action.String(), func(t *testing.T) {
			if err := Execute(context.Background(), platform, action, selection); err != nil {
				t.Fatal(err)
			}
			if got := platform.calls[len(platform.calls)-1]; got.action != action || got.selection != selection {
				t.Fatalf("call = %+v, want action %v selection %+v", got, action, selection)
			}
		})
	}
}

func TestExecuteRejectsNonCanonicalPathBeforePlatformMutation(t *testing.T) {
	platform := &recordingPlatform{}
	path := filepath.Dir(testConfigPath(t)) + string(filepath.Separator) + ".." + string(filepath.Separator) + "config.yaml"
	if err := Execute(context.Background(), platform, Install, Selection{ConfigPath: path, StateRoot: testStatePath(t)}); !errors.Is(err, ErrInvalidConfigPath) {
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
	action    Action
	selection Selection
}

type recordingPlatform struct{ calls []serviceCall }

func (p *recordingPlatform) Apply(_ context.Context, action Action, selection Selection) error {
	p.calls = append(p.calls, serviceCall{action: action, selection: selection})
	return nil
}

func testStatePath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\ClaudeEgressProxy`
	}
	return "/var/lib/claude-egress-proxy"
}

func testConfigPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\ClaudeEgressProxy\config.yaml`
	}
	return "/etc/claude-egress-proxy/config.yaml"
}
