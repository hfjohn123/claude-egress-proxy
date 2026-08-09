package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"gopkg.in/yaml.v3"
)

type rawConfig struct {
	FormatVersion          *int64          `yaml:"format_version"`
	InstanceID             string          `yaml:"instance_id"`
	StateRoot              string          `yaml:"state_root"`
	PublicListener         *rawPublic      `yaml:"public_listener"`
	AdminListener          *rawAdmin       `yaml:"admin_listener"`
	TLS                    *rawTLS         `yaml:"tls"`
	Resolver               *rawResolver    `yaml:"resolver"`
	OutboundSourceIPv4     *string         `yaml:"outbound_source_ipv4"`
	PublicSelfIPv4s        []string        `yaml:"public_self_ipv4s"`
	PerDeviceCapacity      *int64          `yaml:"per_device_capacity"`
	AbsoluteTunnelLifetime *string         `yaml:"absolute_tunnel_lifetime"`
	GracefulShutdownDrain  *string         `yaml:"graceful_shutdown_drain"`
	Destination            *rawDestination `yaml:"destination"`
	Logging                *rawLogging     `yaml:"logging"`
	Metrics                *rawMetrics     `yaml:"metrics"`
}
type rawPublic struct {
	Addresses  []string `yaml:"addresses"`
	PACEnabled bool     `yaml:"pac_enabled"`
}
type rawAdmin struct {
	Enabled bool    `yaml:"enabled"`
	Address *string `yaml:"address"`
}
type rawTLS struct {
	Mode            string  `yaml:"mode"`
	Hostname        *string `yaml:"hostname"`
	CertificateFile *string `yaml:"certificate_file"`
	PrivateKeyFile  *string `yaml:"private_key_file"`
}
type rawResolver struct {
	Mode    *string `yaml:"mode"`
	Address *string `yaml:"address"`
}
type rawDestination struct {
	Profile                 *string  `yaml:"profile"`
	ExactHosts              []string `yaml:"exact_hosts"`
	Suffixes                []string `yaml:"suffixes"`
	DangerousCustomSuffixes bool     `yaml:"dangerous_custom_suffixes"`
}
type rawLogging struct {
	Sink              *string `yaml:"sink"`
	FilePath          *string `yaml:"file_path"`
	SensitiveMetadata bool    `yaml:"sensitive_metadata"`
}
type rawMetrics struct {
	Enabled bool `yaml:"enabled"`
}

type fieldSpec struct {
	tag         string
	child       map[string]fieldSpec
	sequenceTag string
}

var rootFields = map[string]fieldSpec{
	"format_version": {tag: "!!int"}, "instance_id": {tag: "!!str"}, "state_root": {tag: "!!str"},
	"public_listener":      mapping(map[string]fieldSpec{"addresses": sequence("!!str"), "pac_enabled": {tag: "!!bool"}}),
	"admin_listener":       mapping(map[string]fieldSpec{"enabled": {tag: "!!bool"}, "address": {tag: "!!str"}}),
	"tls":                  mapping(map[string]fieldSpec{"mode": {tag: "!!str"}, "hostname": {tag: "!!str"}, "certificate_file": {tag: "!!str"}, "private_key_file": {tag: "!!str"}}),
	"resolver":             mapping(map[string]fieldSpec{"mode": {tag: "!!str"}, "address": {tag: "!!str"}}),
	"outbound_source_ipv4": {tag: "!!str"}, "public_self_ipv4s": sequence("!!str"), "per_device_capacity": {tag: "!!int"},
	"absolute_tunnel_lifetime": {tag: "!!str"}, "graceful_shutdown_drain": {tag: "!!str"},
	"destination": mapping(map[string]fieldSpec{"profile": {tag: "!!str"}, "exact_hosts": sequence("!!str"), "suffixes": sequence("!!str"), "dangerous_custom_suffixes": {tag: "!!bool"}}),
	"logging":     mapping(map[string]fieldSpec{"sink": {tag: "!!str"}, "file_path": {tag: "!!str"}, "sensitive_metadata": {tag: "!!bool"}}),
	"metrics":     mapping(map[string]fieldSpec{"enabled": {tag: "!!bool"}}),
}

func mapping(children map[string]fieldSpec) fieldSpec {
	return fieldSpec{tag: "!!map", child: children}
}
func sequence(tag string) fieldSpec { return fieldSpec{tag: "!!seq", sequenceTag: tag} }

func Decode(doc []byte) (Config, error) {
	if len(doc) == 0 || len(doc) > contract.V1().ConfigBytes || !utf8.Valid(doc) || bytes.HasPrefix(doc, []byte{0xef, 0xbb, 0xbf}) {
		return Config{}, fmt.Errorf("%w", ErrSyntax)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(doc))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return Config{}, fmt.Errorf("%w", ErrSyntax)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode || len(document.Content[0].Content) == 0 {
		return Config{}, fmt.Errorf("%w", ErrSyntax)
	}
	if err := validateMapping(document.Content[0], rootFields); err != nil {
		return Config{}, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("%w", ErrSyntax)
	}
	var raw rawConfig
	if err := document.Content[0].Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("%w", ErrValue)
	}
	return validateRaw(raw)
}

func validateMapping(node *yaml.Node, fields map[string]fieldSpec) error {
	if node.Kind != yaml.MappingNode || node.Tag != "!!map" || node.Anchor != "" {
		return fmt.Errorf("%w", ErrSyntax)
	}
	seen := map[string]struct{}{}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" {
			return fmt.Errorf("%w", ErrSyntax)
		}
		if _, ok := seen[key.Value]; ok {
			return fmt.Errorf("%w", ErrSyntax)
		}
		seen[key.Value] = struct{}{}
		spec, ok := fields[key.Value]
		if !ok {
			return errors.Join(ErrSyntax, ErrUnknownField)
		}
		if err := validateShape(value, spec); err != nil {
			return err
		}
	}
	return nil
}
func validateShape(node *yaml.Node, spec fieldSpec) error {
	if node.Anchor != "" || node.Kind == yaml.AliasNode || node.Tag != spec.tag {
		return fmt.Errorf("%w", ErrSyntax)
	}
	switch spec.tag {
	case "!!map":
		return validateMapping(node, spec.child)
	case "!!seq":
		if node.Kind != yaml.SequenceNode {
			return fmt.Errorf("%w", ErrSyntax)
		}
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode || item.Anchor != "" || item.Tag != spec.sequenceTag {
				return fmt.Errorf("%w", ErrSyntax)
			}
		}
	default:
		if node.Kind != yaml.ScalarNode {
			return fmt.Errorf("%w", ErrSyntax)
		}
	}
	return nil
}
