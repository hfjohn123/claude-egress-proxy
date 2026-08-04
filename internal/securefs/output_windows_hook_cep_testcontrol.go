//go:build windows && cep_testcontrol

package securefs

import "context"

type windowsOutputCommitHookKey struct{}

func ContextWithWindowsOutputCommitHookForTest(ctx context.Context, hook func() error) context.Context {
	return context.WithValue(ctx, windowsOutputCommitHookKey{}, hook)
}

func winOutputCommitHook(ctx context.Context) error {
	hook, _ := ctx.Value(windowsOutputCommitHookKey{}).(func() error)
	if hook == nil {
		return nil
	}
	return hook()
}
