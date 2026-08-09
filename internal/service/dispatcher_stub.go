//go:build !windows

package service

import "context"

func RunWindowsService(func(context.Context) int) (bool, int) { return false, 0 }
