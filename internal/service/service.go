// Package service owns the privileged service-manager boundary.
package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
)

// Action is one closed service-manager operation.
type Action uint8

const (
	ActionInvalid Action = iota
	Install
	Uninstall
	Start
	Stop
)

func (a Action) String() string {
	switch a {
	case Install:
		return "install"
	case Uninstall:
		return "uninstall"
	case Start:
		return "start"
	case Stop:
		return "stop"
	default:
		return "invalid"
	}
}

var (
	ErrInvalidAction     = errors.New("service action")
	ErrInvalidConfigPath = errors.New("service config path")
	ErrUnsupported       = errors.New("service platform unsupported")
)

// Platform performs a selected operation only after Execute has validated its
// canonical config selector. Platform implementations must fail before mutating
// a service owned by a different selector.
type Platform interface {
	Apply(context.Context, Action, string) error
}

// Execute validates the stable service selector then invokes one platform seam.
func Execute(ctx context.Context, platform Platform, action Action, configPath string) error {
	if platform == nil {
		return ErrUnsupported
	}
	if action < Install || action > Stop {
		return ErrInvalidAction
	}
	if !canonicalAbsolute(configPath) {
		return ErrInvalidConfigPath
	}
	return platform.Apply(ctx, action, configPath)
}

func canonicalAbsolute(path string) bool {
	return path != "" && !strings.ContainsRune(path, '\x00') && filepath.IsAbs(path) && filepath.Clean(path) == path
}

// Undo reverts one completed external mutation.
type Undo func(context.Context) error

// Step performs one external mutation and returns its rollback, if any.
type Step func(context.Context) (Undo, error)

// RunTransaction rolls back every completed step in reverse order. The first
// failure is returned; rollback failures do not permit a partial success.
func RunTransaction(ctx context.Context, steps []Step) error {
	undos := make([]Undo, 0, len(steps))
	for _, step := range steps {
		undo, err := step(ctx)
		if err == nil {
			if undo != nil {
				undos = append(undos, undo)
			}
			continue
		}
		for i := len(undos) - 1; i >= 0; i-- {
			if rollbackErr := undos[i](context.WithoutCancel(ctx)); rollbackErr != nil {
				err = errors.Join(err, rollbackErr)
			}
		}
		return err
	}
	return nil
}
