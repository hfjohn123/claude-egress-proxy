package cli

import (
	"bytes"
	"strings"
	"testing"
)

const (
	absConfig = "/etc/claude-egress-proxy/config.yaml"
	absState  = "/var/lib/claude-egress-proxy"
	absPAC    = "/var/lib/claude-egress-proxy/proxy.pac"
)

func TestUsageBytesCatchChangedOrMalformedUsageOutput(t *testing.T) {
	tests := []struct {
		name string
		got  []byte
		want string
	}{
		{"root", UsageRoot, "usage: claude-egress-proxy [--config <absolute-file>] <command>\n"},
		{"init", UsageInit, "usage: claude-egress-proxy [--config <absolute-file>] init [--state-root <absolute-directory>]\n"},
		{"credential group", UsageCredential, "usage: claude-egress-proxy [--config <absolute-file>] credential <subcommand>\n"},
		{"credential add", UsageCredentialAdd, "usage: claude-egress-proxy [--config <absolute-file>] credential add --device <device-identifier>\n"},
		{"credential revoke", UsageCredentialRevoke, "usage: claude-egress-proxy [--config <absolute-file>] credential revoke --record <record-id>\n"},
		{"credential purge", UsageCredentialPurge, "usage: claude-egress-proxy [--config <absolute-file>] credential purge --record <record-id>\n"},
		{"credential list", UsageCredentialList, "usage: claude-egress-proxy [--config <absolute-file>] credential list\n"},
		{"admin token", UsageAdminTokenRotate, "usage: claude-egress-proxy [--config <absolute-file>] admin-token rotate\n"},
		{"pac", UsagePAC, "usage: claude-egress-proxy [--config <absolute-file>] pac --output <absolute-file>\n"},
		{"check config", UsageCheckConfig, "usage: claude-egress-proxy [--config <absolute-file>] check config\n"},
		{"check health", UsageCheckHealth, "usage: claude-egress-proxy check health --address <loopback-IP:port>\n"},
		{"check network", UsageCheckNetwork, "usage: claude-egress-proxy [--config <absolute-file>] check network [--public-ip-url <https-url>]\n"},
		{"service", UsageService, "usage: claude-egress-proxy [--config <absolute-file>] service <install|uninstall|start|stop>\n"},
		{"serve", UsageServe, "usage: claude-egress-proxy [--config <absolute-file>] serve\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := string(test.got); got != test.want {
				t.Fatalf("usage = %q, want %q", got, test.want)
			}
			if bytes.Count(test.got, []byte{'\n'}) != 1 || bytes.Contains(test.got, []byte{'\r'}) {
				t.Fatalf("usage line must contain one LF and no CR: %q", test.got)
			}
		})
	}
}

func TestParseAcceptsOnlyEachFrozenCommandGrammar(t *testing.T) {
	type acceptedCase struct {
		name    string
		argv    []string
		command Command
		action  ServiceAction
		config  bool
	}
	accepted := []acceptedCase{
		{"serve", []string{"serve"}, Serve, ServiceActionNone, true},
		{"init", []string{"init"}, Init, ServiceActionNone, true},
		{"init state root", []string{"init", "--state-root", absState}, Init, ServiceActionNone, true},
		{"check config", []string{"check", "config"}, CheckConfig, ServiceActionNone, true},
		{"credential add", []string{"credential", "add", "--device", "laptop-1"}, CredentialAdd, ServiceActionNone, true},
		{"credential revoke", []string{"credential", "revoke", "--record", strings.Repeat("a", 32)}, CredentialRevoke, ServiceActionNone, true},
		{"credential purge", []string{"credential", "purge", "--record", strings.Repeat("b", 32)}, CredentialPurge, ServiceActionNone, true},
		{"credential list", []string{"credential", "list"}, CredentialList, ServiceActionNone, true},
		{"admin token rotate", []string{"admin-token", "rotate"}, AdminTokenRotate, ServiceActionNone, true},
		{"pac", []string{"pac", "--output", absPAC}, PAC, ServiceActionNone, true},
		{"check health", []string{"check", "health", "--address", "127.0.0.1:9090"}, CheckHealth, ServiceActionNone, false},
		{"check network", []string{"check", "network"}, CheckNetwork, ServiceActionNone, true},
		{"check network public url", []string{"check", "network", "--public-ip-url", "https://echo.example/"}, CheckNetwork, ServiceActionNone, true},
		{"service install", []string{"service", "install"}, Service, ServiceInstall, true},
		{"service uninstall", []string{"service", "uninstall"}, Service, ServiceUninstall, true},
		{"service start", []string{"service", "start"}, Service, ServiceStart, true},
		{"service stop", []string{"service", "stop"}, Service, ServiceStop, true},
	}
	seen := map[Command]bool{}
	for _, test := range accepted {
		t.Run(test.name, func(t *testing.T) {
			invocation, usage := Parse(test.argv, "linux")
			if usage != nil {
				t.Fatalf("Parse(%q) usage = %q", test.argv, usage.Bytes)
			}
			if invocation.Command != test.command || invocation.ServiceAction != test.action {
				t.Fatalf("Parse(%q) command/action = %v/%v, want %v/%v", test.argv, invocation.Command, invocation.ServiceAction, test.command, test.action)
			}
			seen[test.command] = true
		})
		if test.config {
			argv := append([]string{"--config", absConfig}, test.argv...)
			t.Run(test.name+" with config", func(t *testing.T) {
				invocation, usage := Parse(argv, "linux")
				if usage != nil || invocation.ConfigPath != absConfig || invocation.Command != test.command {
					t.Fatalf("Parse(%q) = %+v, %v; want config-aware invocation", argv, invocation, usage)
				}
			})
		}
	}
	for command := Serve; command <= Service; command++ {
		if !seen[command] {
			t.Fatalf("command %v has no accepted grammar", command)
		}
	}
}

func TestParseRejectsGrammarMutationsThatWouldBroadenTheCommandSurface(t *testing.T) {
	accepted := [][]string{
		{"serve"}, {"init"}, {"init", "--state-root", absState},
		{"credential", "add", "--device", "laptop-1"}, {"credential", "revoke", "--record", strings.Repeat("a", 32)},
		{"credential", "purge", "--record", strings.Repeat("b", 32)}, {"credential", "list"}, {"admin-token", "rotate"},
		{"pac", "--output", absPAC}, {"check", "config"}, {"check", "health", "--address", "127.0.0.1:9090"},
		{"check", "network"}, {"check", "network", "--public-ip-url", "https://echo.example/"},
		{"service", "install"}, {"service", "uninstall"}, {"service", "start"}, {"service", "stop"},
	}
	for _, argv := range accepted {
		for index := range argv {
			deletion := append(append([]string(nil), argv[:index]...), argv[index+1:]...)
			assertUsage(t, deletion, "linux")
			for insertion := 0; insertion <= len(argv); insertion++ {
				repeat := append([]string(nil), argv[:insertion]...)
				repeat = append(repeat, argv[index])
				repeat = append(repeat, argv[insertion:]...)
				assertUsage(t, repeat, "linux")
			}
		}
		for insertion := 0; insertion <= len(argv); insertion++ {
			addition := append([]string(nil), argv[:insertion]...)
			addition = append(addition, "unexpected")
			addition = append(addition, argv[insertion:]...)
			assertUsage(t, addition, "linux")
		}
		for left := range argv {
			for right := left + 1; right < len(argv); right++ {
				reordered := append([]string(nil), argv...)
				reordered[left], reordered[right] = reordered[right], reordered[left]
				assertUsage(t, reordered, "linux")
			}
		}
		equals := append([]string(nil), argv...)
		equalsIndex := 0
		for index, token := range equals {
			if strings.HasPrefix(token, "--") {
				equalsIndex = index
				break
			}
		}
		equals[equalsIndex] += "=value"
		assertUsage(t, equals, "linux")
		misplacedConfig := append(append([]string(nil), argv...), "--config", absConfig)
		assertUsage(t, misplacedConfig, "linux")
	}
	assertUsage(t, []string{"--config", absConfig, "check", "health", "--address", "127.0.0.1:9090"}, "linux")
}

func TestParseRoutesEveryCommandToItsExactUsageLine(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{"serve", []string{"serve", "unexpected"}, "usage: claude-egress-proxy [--config <absolute-file>] serve\n"},
		{"init", []string{"init", "unexpected"}, "usage: claude-egress-proxy [--config <absolute-file>] init [--state-root <absolute-directory>]\n"},
		{"credential add", []string{"credential", "add"}, "usage: claude-egress-proxy [--config <absolute-file>] credential add --device <device-identifier>\n"},
		{"credential revoke", []string{"credential", "revoke"}, "usage: claude-egress-proxy [--config <absolute-file>] credential revoke --record <record-id>\n"},
		{"credential purge", []string{"credential", "purge"}, "usage: claude-egress-proxy [--config <absolute-file>] credential purge --record <record-id>\n"},
		{"credential list", []string{"credential", "list", "unexpected"}, "usage: claude-egress-proxy [--config <absolute-file>] credential list\n"},
		{"admin", []string{"admin-token", "unexpected"}, "usage: claude-egress-proxy [--config <absolute-file>] admin-token rotate\n"},
		{"pac", []string{"pac"}, "usage: claude-egress-proxy [--config <absolute-file>] pac --output <absolute-file>\n"},
		{"check config", []string{"check", "config", "unexpected"}, "usage: claude-egress-proxy [--config <absolute-file>] check config\n"},
		{"check health", []string{"check", "health"}, "usage: claude-egress-proxy check health --address <loopback-IP:port>\n"},
		{"check network", []string{"check", "network", "unexpected"}, "usage: claude-egress-proxy [--config <absolute-file>] check network [--public-ip-url <https-url>]\n"},
		{"service", []string{"service", "unexpected"}, "usage: claude-egress-proxy [--config <absolute-file>] service <install|uninstall|start|stop>\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, usage := Parse(test.argv, "linux")
			if usage == nil || string(usage.Bytes) != test.want {
				t.Fatalf("Parse(%q) usage = %v, want %q", test.argv, usage, test.want)
			}
		})
	}
}

func TestParseUsesTheApplicableUsageForRecognizablePaths(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{"missing top level", nil, "usage: claude-egress-proxy [--config <absolute-file>] <command>\n"},
		{"unknown top level", []string{"unknown"}, "usage: claude-egress-proxy [--config <absolute-file>] <command>\n"},
		{"missing check", []string{"check"}, "usage: claude-egress-proxy [--config <absolute-file>] <command>\n"},
		{"unknown check", []string{"check", "unknown"}, "usage: claude-egress-proxy [--config <absolute-file>] <command>\n"},
		{"missing credential", []string{"credential"}, "usage: claude-egress-proxy [--config <absolute-file>] credential <subcommand>\n"},
		{"unknown credential", []string{"credential", "unknown"}, "usage: claude-egress-proxy [--config <absolute-file>] credential <subcommand>\n"},
		{"missing service", []string{"service"}, "usage: claude-egress-proxy [--config <absolute-file>] service <install|uninstall|start|stop>\n"},
		{"unknown service", []string{"service", "unknown"}, "usage: claude-egress-proxy [--config <absolute-file>] service <install|uninstall|start|stop>\n"},
		{"bad init flag", []string{"init", "--nope"}, "usage: claude-egress-proxy [--config <absolute-file>] init [--state-root <absolute-directory>]\n"},
		{"bad config for serve", []string{"--config", "relative", "serve"}, "usage: claude-egress-proxy [--config <absolute-file>] serve\n"},
		{"admin token always rotate", []string{"admin-token"}, "usage: claude-egress-proxy [--config <absolute-file>] admin-token rotate\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, usage := Parse(test.argv, "linux")
			if usage == nil || string(usage.Bytes) != test.want {
				t.Fatalf("Parse(%q) usage = %v, want %q", test.argv, usage, test.want)
			}
		})
	}
}

func TestParseRejectsInvalidSelectorsBeforeTheyReachHandlers(t *testing.T) {
	tests := []struct {
		name string
		argv []string
	}{
		{"empty device", []string{"credential", "add", "--device", ""}},
		{"device too long", []string{"credential", "add", "--device", strings.Repeat("a", 65)}},
		{"unicode device", []string{"credential", "add", "--device", "laptop-µ"}},
		{"whitespace device", []string{"credential", "add", "--device", "laptop 1"}},
		{"uppercase record", []string{"credential", "revoke", "--record", strings.Repeat("A", 32)}},
		{"short record", []string{"credential", "revoke", "--record", strings.Repeat("a", 31)}},
		{"long record", []string{"credential", "purge", "--record", strings.Repeat("a", 33)}},
		{"unicode record", []string{"credential", "purge", "--record", strings.Repeat("a", 31) + "µ"}},
		{"empty public url", []string{"check", "network", "--public-ip-url", ""}},
		{"alternate loopback", []string{"check", "health", "--address", "127.1:9090"}},
		{"ipv6 zone", []string{"check", "health", "--address", "[::1%lo]:9090"}},
		{"leading zero port", []string{"check", "health", "--address", "127.0.0.1:09090"}},
		{"zero port", []string{"check", "health", "--address", "127.0.0.1:0"}},
		{"too large port", []string{"check", "health", "--address", "[::1]:65536"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { assertUsage(t, test.argv, "linux") })
	}
	if _, usage := Parse([]string{"check", "health", "--address", "[::1]:65535"}, "linux"); usage != nil {
		t.Fatalf("valid IPv6 loopback rejected: %q", usage.Bytes)
	}
}

func TestParseRejectsNonLexicalAbsolutePaths(t *testing.T) {
	tests := []struct {
		name string
		goos string
		argv []string
	}{
		{"linux relative config", "linux", []string{"--config", "config.yaml", "serve"}},
		{"linux double slash", "linux", []string{"--config", "//etc/config.yaml", "serve"}},
		{"linux nul", "linux", []string{"pac", "--output", "/tmp/x\x00.pac"}},
		{"windows drive relative", "windows", []string{"--config", "C:config.yaml", "serve"}},
		{"windows root relative", "windows", []string{"--config", "\\config.yaml", "serve"}},
		{"windows extended path", "windows", []string{"--config", "\\\\?\\C:\\config.yaml", "serve"}},
		{"windows device path", "windows", []string{"--config", "\\\\.\\C:\\config.yaml", "serve"}},
		{"windows empty unc server", "windows", []string{"--config", "\\\\\\share\\config.yaml", "serve"}},
		{"windows empty unc share", "windows", []string{"--config", "\\\\server\\\\config.yaml", "serve"}},
		{"unsupported platform", "darwin", []string{"serve"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { assertUsage(t, test.argv, test.goos) })
	}
	for _, path := range []string{"C:\\config.yaml", "C:/config.yaml", "\\\\server\\share\\config.yaml", "//server/share/config.yaml"} {
		if _, usage := Parse([]string{"--config", path, "serve"}, "windows"); usage != nil {
			t.Fatalf("windows path %q rejected: %q", path, usage.Bytes)
		}
	}
}

func assertUsage(t *testing.T, argv []string, goos string) {
	t.Helper()
	if _, usage := Parse(argv, goos); usage == nil {
		t.Fatalf("Parse(%q, %q) succeeded; malformed argv broadened the command grammar", argv, goos)
	}
}
