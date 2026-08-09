package pac

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
)

var ErrInvalidEndpoint = errors.New("invalid PAC endpoint")
var ErrInvalidVisibility = errors.New("invalid PAC visibility")
var ErrInvalidPolicy = errors.New("invalid PAC policy")

type ProxyEndpoint struct{ directive string }
type Visibility uint8

const (
	VisibilityInvalid Visibility = iota
	VisibilityPublic
	VisibilityLocal
)

func RemoteEndpoint(host string, port uint16) (ProxyEndpoint, error) {
	if port == 0 || !canonicalHost(host) {
		return ProxyEndpoint{}, ErrInvalidEndpoint
	}
	return ProxyEndpoint{fmt.Sprintf("HTTPS %s:%d", host, port)}, nil
}
func LoopbackEndpoint(addr netip.Addr, port uint16) (ProxyEndpoint, error) {
	if port == 0 || addr.String() != "127.0.0.1" {
		return ProxyEndpoint{}, ErrInvalidEndpoint
	}
	return ProxyEndpoint{fmt.Sprintf("PROXY 127.0.0.1:%d", port)}, nil
}
func canonicalHost(h string) bool { n, e := policy.NormalizeHostname(h); return e == nil && n == h }
func Render(p policy.Policy, endpoint ProxyEndpoint, v Visibility) ([]byte, error) {
	if endpoint.directive == "" {
		return nil, ErrInvalidEndpoint
	}
	var rules policy.Rules
	var label string
	switch v {
	case VisibilityPublic:
		rules = p.BuiltInRules()
		label = "public"
	case VisibilityLocal:
		rules = p.LocalRules()
		label = "local"
	default:
		return nil, ErrInvalidVisibility
	}
	if p.Profile() == "" || len(rules.ExactHosts())+len(rules.Suffixes()) == 0 {
		return nil, ErrInvalidPolicy
	}
	conditions := make([]string, 0, len(rules.ExactHosts())+len(rules.Suffixes()))
	for _, h := range rules.ExactHosts() {
		conditions = append(conditions, "host === "+strconv.QuoteToASCII(h))
	}
	for _, h := range rules.Suffixes() {
		q := strconv.QuoteToASCII(h)
		conditions = append(conditions, "host === "+q+" || dnsDomainIs(host, \"."+h+"\")")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "// claude-egress-proxy PAC v1; profile=%s; visibility=%s\nfunction FindProxyForURL(url, host) {\n  host = host.toLowerCase();\n  if (host.length > 1 && host.charAt(host.length - 1) === \".\") {\n    host = host.substring(0, host.length - 1);\n  }\n  if (\n", p.Profile(), label)
	for i, c := range conditions {
		if i == 0 {
			fmt.Fprintf(&b, "    %s\n", c)
		} else {
			fmt.Fprintf(&b, "    || %s\n", c)
		}
	}
	fmt.Fprintf(&b, "  ) {\n    return %s;\n  }\n  return \"DIRECT\";\n}\n", strconv.QuoteToASCII(endpoint.directive))
	out := []byte(b.String())
	if len(out) > contract.V1().PACBytes {
		return nil, ErrInvalidEndpoint
	}
	return out, nil
}
