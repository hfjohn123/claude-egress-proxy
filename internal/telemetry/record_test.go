package telemetry

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

func TestRecord(t *testing.T) {
	close, _ := contract.ParseCloseResult("clean")
	r, err := TunnelClosed(time.Date(2026, 8, 4, 12, 0, 0, 0, time.FixedZone("x", -3600)), close, &SensitiveMetadata{DestinationHostname: "api.example.com", DeviceIdentifier: "device-1", SourcePrefix: netip.MustParsePrefix("192.0.2.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"timestamp":"2026-08-04T13:00:00Z","level":"info","event":"tunnel_closed","reason":"clean","destination_hostname":"api.example.com","device_identifier":"device-1","source_prefix":"192.0.2.0/24","duration_ms":0,"bytes_client_to_origin":0,"bytes_origin_to_client":0}`
	if r.JSON() != want {
		t.Fatalf("got %s", r.JSON())
	}
	if strings.ContainsAny(r.JSON(), "\r\n") || len(r.JSON()) > 2047 {
		t.Fatal("unsafe record")
	}
}
