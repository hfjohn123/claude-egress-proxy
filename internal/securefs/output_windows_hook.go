//go:build windows && !cep_testcontrol

package securefs

import "context"

func winOutputCommitHook(context.Context) error { return nil }
