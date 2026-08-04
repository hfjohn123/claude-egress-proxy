//go:build linux && !cep_testcontrol

package securefs

import "context"

func linuxOutputCommitHook(context.Context) error { return nil }
