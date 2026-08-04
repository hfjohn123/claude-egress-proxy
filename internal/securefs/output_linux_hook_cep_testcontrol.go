//go:build linux && cep_testcontrol

package securefs

import "context"

type outputCommitHookKey struct{}

func ContextWithOutputCommitHookForTest(ctx context.Context, hook func() error) context.Context {
	return context.WithValue(ctx, outputCommitHookKey{}, hook)
}

func linuxOutputCommitHook(ctx context.Context) error {
	hook, _ := ctx.Value(outputCommitHookKey{}).(func() error)
	if hook == nil {
		return nil
	}
	return hook()
}
