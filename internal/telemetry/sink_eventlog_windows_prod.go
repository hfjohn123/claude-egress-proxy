//go:build windows && !cep_testcontrol

package telemetry

import "golang.org/x/sys/windows/svc/eventlog"

func openEventLog(source string) (eventLog, error) { return eventlog.Open(source) }
