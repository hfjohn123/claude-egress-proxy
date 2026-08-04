package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/pac"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestPACPathFailuresMapToFixedDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want contract.DiagnosticCode
	}{
		{securefs.ErrUnsafePath, contract.D004}, {securefs.ErrIdentityChanged, contract.D004},
		{securefs.ErrPermissions, contract.D004}, {securefs.ErrUnsupportedInspection, contract.D010},
		{errors.New("io"), contract.D010},
	} {
		if got := pacPathCode(tc.err); got != tc.want {
			t.Fatalf("%v = %v want %v", tc.err, got, tc.want)
		}
	}
}

type pacLoadedStub struct{ cfg config.Config }

func (s pacLoadedStub) Config() config.Config { return s.cfg }
func (pacLoadedStub) Close() error            { return nil }

type pacDiagnostic contract.DiagnosticCode

func (d pacDiagnostic) Error() string                           { return "test diagnostic" }
func (d pacDiagnostic) DiagnosticCode() contract.DiagnosticCode { return contract.DiagnosticCode(d) }

func TestPACHandlerOrdersValidationBeforeOutputAndUsesSelectedConfig(t *testing.T) {
	cfg := pacConfig(t, "destination:\n  exact_hosts: [local.example]\n")
	for _, tc := range []struct {
		name                          string
		loadErr, policyErr, renderErr error
		want                          contract.DiagnosticCode
	}{
		{"config D001", pacDiagnostic(contract.D001), nil, nil, contract.D001},
		{"config D002", pacDiagnostic(contract.D002), nil, nil, contract.D002},
		{"config", pacDiagnostic(contract.D003), nil, nil, contract.D003},
		{"config D004", pacDiagnostic(contract.D004), nil, nil, contract.D004},
		{"config D010", pacDiagnostic(contract.D010), nil, nil, contract.D010},
		{"policy", nil, errors.New("policy"), nil, contract.D003},
		{"render", nil, nil, errors.New("render"), contract.D003},
	} {
		t.Run(tc.name, func(t *testing.T) {
			published := false
			loadedPath := ""
			h := newPACHandler(pacDependencies{
				defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: "default.yaml"}, nil },
				load: func(path string) (pacLoaded, error) {
					loadedPath = path
					if tc.loadErr != nil {
						return nil, tc.loadErr
					}
					return pacLoadedStub{cfg}, nil
				},
				policyLoad: func(n string, c policy.CustomRules) (policy.Policy, error) {
					if tc.policyErr != nil {
						return policy.Policy{}, tc.policyErr
					}
					return policy.Load(n, c)
				},
				render: func(p policy.Policy, e pac.ProxyEndpoint, v pac.Visibility) ([]byte, error) {
					if tc.renderErr != nil {
						return nil, tc.renderErr
					}
					return []byte("PAC"), nil
				},
				publish: func(context.Context, cli.Invocation, []byte) error { published = true; return nil },
			})
			got := h(context.Background(), cli.Invocation{ConfigPath: "explicit.yaml", PACOutput: "output.pac"})
			if got.ExitCode != 1 || string(got.Stderr) != string(contract.Fatal(tc.want)) || len(got.Stdout) != 0 || published || loadedPath != "explicit.yaml" {
				t.Fatalf("result=%+v publish=%v load=%q", got, published, loadedPath)
			}
		})
	}
	var body []byte
	h := newPACHandler(pacDependencies{defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: "default.yaml"}, nil }, load: func(path string) (pacLoaded, error) {
		if path != "default.yaml" {
			t.Fatalf("path=%q", path)
		}
		return pacLoadedStub{cfg}, nil
	}, policyLoad: policy.Load, render: func(p policy.Policy, e pac.ProxyEndpoint, v pac.Visibility) ([]byte, error) {
		if !p.MatchHost("local.example") || v != pac.VisibilityLocal {
			t.Fatal("local rules not rendered")
		}
		return []byte("exact-pac"), nil
	}, publish: func(_ context.Context, _ cli.Invocation, b []byte) error {
		body = append([]byte(nil), b...)
		return nil
	}})
	if got := h(context.Background(), cli.Invocation{}); got.ExitCode != 0 || len(got.Stdout) != 0 || len(got.Stderr) != 0 || string(body) != "exact-pac" {
		t.Fatalf("success=%+v body=%q", got, body)
	}
}

func TestPACHandlerRejectsIPv6OnlyLoopbackBeforeOutput(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	cfg, err := config.Decode([]byte(fmt.Sprintf("format_version: 1\ninstance_id: 000102030405060708090a0b0c0d0e0f\nstate_root: %q\npublic_listener:\n  addresses: ['[::1]:443']\ntls:\n  mode: insecure_loopback\n", state)))
	if err != nil {
		t.Fatal(err)
	}
	published := false
	h := newPACHandler(pacDependencies{load: func(string) (pacLoaded, error) { return pacLoadedStub{cfg}, nil }, policyLoad: policy.Load, render: pac.Render, publish: func(context.Context, cli.Invocation, []byte) error { published = true; return nil }})
	got := h(context.Background(), cli.Invocation{ConfigPath: "x"})
	if got.ExitCode != 1 || string(got.Stderr) != string(contract.Fatal(contract.D003)) || published {
		t.Fatalf("result=%+v published=%v", got, published)
	}
}

func pacConfig(t *testing.T, extra string) config.Config {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	doc := fmt.Sprintf("format_version: 1\ninstance_id: 000102030405060708090a0b0c0d0e0f\nstate_root: %q\ntls:\n  mode: acme\n  hostname: proxy.example.com\n%s", state, extra)
	cfg, err := config.Decode([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
