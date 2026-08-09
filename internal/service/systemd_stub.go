//go:build !linux && !windows

package service

import "context"

type unsupportedPlatform struct{}

// NewPlatform returns an adapter that fails closed on unsupported hosts.
func NewPlatform() Platform { return unsupportedPlatform{} }

func (unsupportedPlatform) Apply(context.Context, Action, Selection) error { return ErrUnsupported }
