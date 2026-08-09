// Package telemetry exposes the proxy's closed metrics and application records.
package telemetry

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

var ErrInvalidRecord = errors.New("telemetry: invalid record")

type SensitiveMetadata struct {
	DestinationHostname string
	DeviceIdentifier    string
	SourcePrefix        netip.Prefix
	DurationMillis      uint64
	Bytes               contract.ByteTotals
}
type Record struct{ json string }

func (r Record) JSON() string { return r.json }

func TunnelClosed(at time.Time, reason contract.CloseResult, sensitive *SensitiveMetadata) (Record, error) {
	if !closed(reason) {
		return Record{}, ErrInvalidRecord
	}
	level, ok := generatedRecordLevel("tunnel_closed", reason.String())
	if !ok {
		return Record{}, ErrInvalidRecord
	}
	return build(at, level, "tunnel_closed", reason.String(), sensitive)
}
func ReloadRecord(at time.Time, kind contract.ReloadKind, result contract.ReloadResult) (Record, error) {
	if !reloadKind(kind) || !reloadResult(result) || result.String() == "success" {
		return Record{}, ErrInvalidRecord
	}
	reason := kind.String() + "_" + result.String()
	level, ok := generatedRecordLevel("reload", reason)
	if !ok {
		return Record{}, ErrInvalidRecord
	}
	return build(at, level, "reload", reason, nil)
}
func ServiceState(at time.Time, reason contract.ServiceStateReason) (Record, error) {
	if !serviceReason(reason) {
		return Record{}, ErrInvalidRecord
	}
	level, ok := generatedRecordLevel("service_state", reason.String())
	if !ok {
		return Record{}, ErrInvalidRecord
	}
	return build(at, level, "service_state", reason.String(), nil)
}
func build(at time.Time, level, event, reason string, s *SensitiveMetadata) (Record, error) {
	if at.IsZero() || at.UTC().Year() < 0 || at.UTC().Year() > 9999 {
		return Record{}, ErrInvalidRecord
	}
	ts := at.UTC().Format(time.RFC3339Nano)
	if len(ts) < 20 || len(ts) > 30 || !strings.HasSuffix(ts, "Z") {
		return Record{}, ErrInvalidRecord
	}
	var b strings.Builder
	b.Grow(320)
	b.WriteString(`{"timestamp":`)
	quote(&b, ts)
	b.WriteString(`,"level":`)
	quote(&b, level)
	b.WriteString(`,"event":`)
	quote(&b, event)
	b.WriteString(`,"reason":`)
	quote(&b, reason)
	if s != nil {
		if !validSensitive(s) {
			return Record{}, ErrInvalidRecord
		}
		b.WriteString(`,"destination_hostname":`)
		quote(&b, s.DestinationHostname)
		b.WriteString(`,"device_identifier":`)
		quote(&b, s.DeviceIdentifier)
		b.WriteString(`,"source_prefix":`)
		quote(&b, s.SourcePrefix.String())
		b.WriteString(`,"duration_ms":`)
		b.WriteString(strconv.FormatUint(s.DurationMillis, 10))
		b.WriteString(`,"bytes_client_to_origin":`)
		b.WriteString(strconv.FormatUint(s.Bytes.ClientToOrigin, 10))
		b.WriteString(`,"bytes_origin_to_client":`)
		b.WriteString(strconv.FormatUint(s.Bytes.OriginToClient, 10))
	}
	b.WriteByte('}')
	if b.Len() > GeneratedRecordSchema.MaxBytes || strings.ContainsAny(b.String(), "\r\n") {
		return Record{}, ErrInvalidRecord
	}
	return Record{json: b.String()}, nil
}
func quote(b *strings.Builder, s string) { b.WriteString(strconv.Quote(s)) }
func validSensitive(s *SensitiveMetadata) bool {
	return validHost(s.DestinationHostname) && validDevice(s.DeviceIdentifier) && validPrefix(s.SourcePrefix)
}
func validHost(host string) bool {
	if addr, err := netip.ParseAddr(host); len(host) < 1 || len(host) > 253 || strings.ToLower(host) != host || err == nil && addr.IsValid() {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || !alnum(label[0]) || !alnum(label[len(label)-1]) {
			return false
		}
		for i := range label {
			if !alnum(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}
func alnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
func validDevice(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := range s {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("._~-", rune(c))) {
			return false
		}
	}
	return true
}
func validPrefix(p netip.Prefix) bool {
	return p.IsValid() && p == p.Masked() && ((p.Addr().Is4() && p.Bits() == 24) || (p.Addr().Is6() && p.Bits() == 64)) && len(p.String()) <= 43
}
func closed(v contract.CloseResult) bool {
	_, ok := contract.ParseCloseResult(safeString(func() string { return v.String() }))
	return ok
}
func reloadKind(v contract.ReloadKind) bool {
	_, ok := contract.ParseReloadKind(safeString(func() string { return v.String() }))
	return ok
}
func reloadResult(v contract.ReloadResult) bool {
	_, ok := contract.ParseReloadResult(safeString(func() string { return v.String() }))
	return ok
}
func serviceReason(v contract.ServiceStateReason) bool {
	_, ok := contract.ParseServiceStateReason(safeString(func() string { return v.String() }))
	return ok
}
func safeString(f func() string) (out string) {
	defer func() {
		if recover() != nil {
			out = ""
		}
	}()
	return f()
}
