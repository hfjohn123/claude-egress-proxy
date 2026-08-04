package pac

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
)

func TestRenderPublicExcludesCustomAndUsesRemoteHTTPS(t *testing.T) {
	p, err := policy.Load("code", policy.CustomRules{ExactHosts: []string{"local.example"}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := RemoteEndpoint("proxy.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(p, e, VisibilityPublic)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `return "HTTPS proxy.example:443";`) || strings.Contains(s, "local.example") || !strings.HasSuffix(s, "}\n") {
		t.Fatalf("PAC = %q", s)
	}
}

func TestLoopbackEndpointRejectsNonLoopback(t *testing.T) {
	if _, err := LoopbackEndpoint(netip.MustParseAddr("127.0.0.2"), 8443); err == nil {
		t.Fatal("accepted noncanonical loopback")
	}
}
