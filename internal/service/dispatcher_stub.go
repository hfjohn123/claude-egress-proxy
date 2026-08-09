//go:build !windows

package service

import "context"

func RunWindowsService(func(context.Context) (bool, uint32)) (bool, int) { return false, 0 }
func IsSCMContext(context.Context) bool                                  { return false }
