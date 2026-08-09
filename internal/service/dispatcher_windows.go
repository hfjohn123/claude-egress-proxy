//go:build windows

package service

import (
	"context"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"golang.org/x/sys/windows/svc"
)

type scmContextKey struct{}

func IsSCMContext(ctx context.Context) bool {
	value, _ := ctx.Value(scmContextKey{}).(bool)
	return value
}

const windowsStopWaitHint = 25_000

type scmHandler struct {
	run   func(context.Context) (bool, uint32)
	clock timebase.Clock
}

func (h scmHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), scmContextKey{}, true))
	defer cancel()
	type exitStatus struct {
		specific bool
		code     uint32
	}
	done := make(chan exitStatus, 1)
	go func() {
		specific, code := h.run(ctx)
		done <- exitStatus{specific: specific, code: code}
	}()
	clock := h.clock
	if clock == nil {
		clock = timebase.Real{}
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown}
	for {
		select {
		case exit := <-done:
			return exit.specific, exit.code
		case req := <-requests:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				cancel()
				checkpoint := uint32(1)
				status <- svc.Status{State: svc.StopPending, WaitHint: windowsStopWaitHint, CheckPoint: checkpoint}
				ticker := clock.NewTicker(time.Second)
				deadline := clock.NewTimer(25 * time.Second)
				defer ticker.Stop()
				defer deadline.Stop()
				for {
					select {
					case exit := <-done:
						return exit.specific, exit.code
					case <-ticker.C():
						checkpoint++
						status <- svc.Status{State: svc.StopPending, WaitHint: windowsStopWaitHint, CheckPoint: checkpoint}
					case <-deadline.C():
						return false, 1
					}
				}
			}
		}
	}
}

// RunWindowsService enters the SCM dispatcher when launched by SCM. It
// returns handled=false for an ordinary console invocation.
func RunWindowsService(run func(context.Context) (bool, uint32)) (handled bool, code int) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, 0
	}
	if err := svc.Run(WindowsServiceName, scmHandler{run: run}); err != nil {
		return true, 1
	}
	return true, 0
}
