//go:build windows

package service

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestSCMStopPublishesWaitHintAndProgress(t *testing.T) {
	release := make(chan struct{})
	handler := scmHandler{run: func(ctx context.Context) (bool, uint32) {
		<-ctx.Done()
		<-release
		return false, 0
	}}
	requests := make(chan svc.ChangeRequest, 1)
	statuses := make(chan svc.Status, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.Execute(nil, requests, statuses)
	}()
	<-statuses // start pending
	<-statuses // running
	requests <- svc.ChangeRequest{Cmd: svc.PreShutdown}
	first := <-statuses
	if first.State != svc.StopPending || first.WaitHint != 25_000 || first.CheckPoint != 1 {
		t.Fatalf("first stop status=%+v", first)
	}
	select {
	case progress := <-statuses:
		if progress.State != svc.StopPending || progress.WaitHint != 25_000 || progress.CheckPoint <= first.CheckPoint {
			t.Fatalf("progress status=%+v", progress)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("SCM stop checkpoint did not advance")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not finish")
	}
}
