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

type outputPublishedHookKey struct{}

func ContextWithOutputPublishedHookForTest(ctx context.Context, hook func()) context.Context {
	return context.WithValue(ctx, outputPublishedHookKey{}, hook)
}

func linuxOutputPublishedHook(ctx context.Context) {
	hook, _ := ctx.Value(outputPublishedHookKey{}).(func())
	if hook != nil {
		hook()
	}
}
