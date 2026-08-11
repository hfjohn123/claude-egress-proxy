// Package cli parses the closed command grammar without filesystem or network access.
package cli

import (
	"strconv"
	"strings"
)

type Command uint8

const (
	CommandInvalid Command = iota
	Serve
	Init
	CredentialAdd
	CredentialRevoke
	CredentialPurge
	CredentialList
	AdminTokenRotate
	PAC
	ConfigApply
	CheckConfig
	CheckHealth
	CheckNetwork
	Service
)

type ServiceAction uint8

const (
	ServiceActionNone ServiceAction = iota
	ServiceInstall
	ServiceUninstall
	ServiceStart
	ServiceStop
)

// Invocation is the typed, secret-free result of parsing one command line.
type Invocation struct {
	Command                                              Command
	ConfigPath, ConfigInput, StateRoot, Device, RecordID string
	PACOutput, HealthAddress, PublicIPURL                string
	ServiceAction                                        ServiceAction
}

// Parse accepts only the frozen argv grammar for the supplied platform.
func Parse(args []string, goos string) (Invocation, *UsageError) {
	validPlatform := goos == "linux" || goos == "windows"
	configPath := ""
	commonInvalid := !validPlatform
	if len(args) > 0 && strings.HasPrefix(args[0], "--config=") {
		return Invocation{}, malformedCommonUsage(args[1:], goos)
	}
	if len(args) > 0 && args[0] == "--config" {
		if len(args) < 2 {
			return Invocation{}, usage(UsageRoot)
		}
		configPath = args[1]
		if !absolutePath(configPath, goos) {
			commonInvalid = true
		}
		args = args[2:]
		if len(args) > 0 && args[0] == "--config" {
			if len(args) < 2 {
				return Invocation{}, usage(UsageRoot)
			}
			return Invocation{}, malformedCommonUsage(args[2:], goos)
		}
		if len(args) > 0 && strings.HasPrefix(args[0], "--config=") {
			return Invocation{}, malformedCommonUsage(args[1:], goos)
		}
	}

	invocation, err := parseCommand(args, goos)
	if err != nil {
		return Invocation{}, err
	}
	if invocation.Command == CheckHealth && configPath != "" {
		return Invocation{}, usage(UsageCheckHealth)
	}
	if commonInvalid {
		return Invocation{}, usageFor(invocation.Command)
	}
	invocation.ConfigPath = configPath
	return invocation, nil
}

func malformedCommonUsage(args []string, goos string) *UsageError {
	for len(args) > 0 {
		switch {
		case args[0] == "--config":
			if len(args) < 2 {
				return usage(UsageRoot)
			}
			args = args[2:]
		case strings.HasPrefix(args[0], "--config="):
			args = args[1:]
		default:
			invocation, err := parseCommand(args, goos)
			if err != nil {
				return err
			}
			return usageFor(invocation.Command)
		}
	}
	return usage(UsageRoot)
}

func parseCommand(args []string, goos string) (Invocation, *UsageError) {
	if len(args) == 0 {
		return Invocation{}, usage(UsageRoot)
	}
	switch args[0] {
	case "serve":
		if len(args) != 1 {
			return Invocation{}, usage(UsageServe)
		}
		return Invocation{Command: Serve}, nil
	case "init":
		if len(args) == 1 {
			return Invocation{Command: Init}, nil
		}
		if len(args) != 3 || args[1] != "--state-root" || !absolutePath(args[2], goos) {
			return Invocation{}, usage(UsageInit)
		}
		return Invocation{Command: Init, StateRoot: args[2]}, nil
	case "credential":
		return parseCredential(args)
	case "admin-token":
		if len(args) != 2 || args[1] != "rotate" {
			return Invocation{}, usage(UsageAdminTokenRotate)
		}
		return Invocation{Command: AdminTokenRotate}, nil
	case "pac":
		if len(args) != 3 || args[1] != "--output" || !absolutePath(args[2], goos) {
			return Invocation{}, usage(UsagePAC)
		}
		return Invocation{Command: PAC, PACOutput: args[2]}, nil
	case "config":
		return parseConfig(args, goos)
	case "check":
		return parseCheck(args)
	case "service":
		return parseService(args)
	default:
		return Invocation{}, usage(UsageRoot)
	}
}

func parseConfig(args []string, goos string) (Invocation, *UsageError) {
	if len(args) != 4 || args[1] != "apply" || args[2] != "--input" || !absolutePath(args[3], goos) {
		return Invocation{}, usage(UsageConfigApply)
	}
	return Invocation{Command: ConfigApply, ConfigInput: args[3]}, nil
}

func parseCredential(args []string) (Invocation, *UsageError) {
	if len(args) < 2 {
		return Invocation{}, usage(UsageCredential)
	}
	switch args[1] {
	case "add":
		if len(args) != 4 || args[2] != "--device" || !deviceID(args[3]) {
			return Invocation{}, usage(UsageCredentialAdd)
		}
		return Invocation{Command: CredentialAdd, Device: args[3]}, nil
	case "revoke":
		if len(args) != 4 || args[2] != "--record" || !recordID(args[3]) {
			return Invocation{}, usage(UsageCredentialRevoke)
		}
		return Invocation{Command: CredentialRevoke, RecordID: args[3]}, nil
	case "purge":
		if len(args) != 4 || args[2] != "--record" || !recordID(args[3]) {
			return Invocation{}, usage(UsageCredentialPurge)
		}
		return Invocation{Command: CredentialPurge, RecordID: args[3]}, nil
	case "list":
		if len(args) != 2 {
			return Invocation{}, usage(UsageCredentialList)
		}
		return Invocation{Command: CredentialList}, nil
	default:
		return Invocation{}, usage(UsageCredential)
	}
}

func parseCheck(args []string) (Invocation, *UsageError) {
	if len(args) < 2 {
		return Invocation{}, usage(UsageRoot)
	}
	switch args[1] {
	case "config":
		if len(args) != 2 {
			return Invocation{}, usage(UsageCheckConfig)
		}
		return Invocation{Command: CheckConfig}, nil
	case "health":
		if len(args) != 4 || args[2] != "--address" || !healthAddress(args[3]) {
			return Invocation{}, usage(UsageCheckHealth)
		}
		return Invocation{Command: CheckHealth, HealthAddress: args[3]}, nil
	case "network":
		if len(args) == 2 {
			return Invocation{Command: CheckNetwork}, nil
		}
		if len(args) != 4 || args[2] != "--public-ip-url" || args[3] == "" {
			return Invocation{}, usage(UsageCheckNetwork)
		}
		return Invocation{Command: CheckNetwork, PublicIPURL: args[3]}, nil
	default:
		return Invocation{}, usage(UsageRoot)
	}
}

func parseService(args []string) (Invocation, *UsageError) {
	if len(args) != 2 {
		return Invocation{}, usage(UsageService)
	}
	var action ServiceAction
	switch args[1] {
	case "install":
		action = ServiceInstall
	case "uninstall":
		action = ServiceUninstall
	case "start":
		action = ServiceStart
	case "stop":
		action = ServiceStop
	default:
		return Invocation{}, usage(UsageService)
	}
	return Invocation{Command: Service, ServiceAction: action}, nil
}

func deviceID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '~' || b == '-') {
			return false
		}
	}
	return true
}

func recordID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func healthAddress(value string) bool {
	port := ""
	switch {
	case len(value) > len("127.0.0.1:") && value[:len("127.0.0.1:")] == "127.0.0.1:":
		port = value[len("127.0.0.1:"):]
	case len(value) > len("[::1]:") && value[:len("[::1]:")] == "[::1]:":
		port = value[len("[::1]:"):]
	default:
		return false
	}
	if len(port) == 0 || port[0] == '0' {
		return false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535
}

func absolutePath(path, goos string) bool {
	if path == "" || containsNUL(path) {
		return false
	}
	switch goos {
	case "linux":
		return path[0] == '/' && (len(path) == 1 || path[1] != '/')
	case "windows":
		if len(path) >= 3 && isLetter(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
			return true
		}
		if len(path) >= 3 && (path[0] == '\\' || path[0] == '/') && path[1] == path[0] && (path[2] == '?' || path[2] == '.') {
			return false
		}
		return uncPath(path, '\\') || uncPath(path, '/')
	default:
		return false
	}
}

func uncPath(path string, separator byte) bool {
	if len(path) < 5 || path[0] != separator || path[1] != separator {
		return false
	}
	start := 2
	serverEnd := start
	for serverEnd < len(path) && path[serverEnd] != separator {
		serverEnd++
	}
	if serverEnd == start || serverEnd == len(path) {
		return false
	}
	for index := serverEnd; index < len(path); index++ {
		if path[index] == separator && (index == len(path)-1 || path[index+1] == separator) {
			return false
		}
	}
	shareStart := serverEnd + 1
	shareEnd := shareStart
	for shareEnd < len(path) && path[shareEnd] != separator {
		shareEnd++
	}
	return shareEnd > shareStart
}

func isLetter(b byte) bool { return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' }

func containsNUL(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == 0 {
			return true
		}
	}
	return false
}
