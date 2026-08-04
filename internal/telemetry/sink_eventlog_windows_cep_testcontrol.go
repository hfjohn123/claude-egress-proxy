//go:build windows && cep_testcontrol

package telemetry

import "golang.org/x/sys/windows/svc/eventlog"

var eventLogOpenForTest = func(source string) (eventLog, error) { return eventlog.Open(source) }

func openEventLog(source string) (eventLog, error) { return eventLogOpenForTest(source) }

func setEventLogOpenForTest(open func(string) (eventLog, error)) func() {
	old := eventLogOpenForTest
	eventLogOpenForTest = open
	return func() { eventLogOpenForTest = old }
}
