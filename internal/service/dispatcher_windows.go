//go:build windows

package service

import (
	"context"

	"golang.org/x/sys/windows/svc"
)

type scmHandler struct{ run func(context.Context) int }

func (h scmHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case code := <-done:
			return false, uint32(code)
		case req := <-requests:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				code := <-done
				return false, uint32(code)
			}
		}
	}
}

// RunWindowsService enters the SCM dispatcher when launched by SCM. It
// returns handled=false for an ordinary console invocation.
func RunWindowsService(run func(context.Context) int) (handled bool, code int) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, 0
	}
	if err := svc.Run(WindowsServiceName, scmHandler{run: run}); err != nil {
		return true, 1
	}
	return true, 0
}
