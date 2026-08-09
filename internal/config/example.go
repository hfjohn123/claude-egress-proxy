package config

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

func RenderExample(instanceID [16]byte, stateRoot string) []byte {
	return []byte(fmt.Sprintf("format_version: 1\ninstance_id: %s\nstate_root: %s\npublic_listener:\n  addresses: [0.0.0.0:443]\n  pac_enabled: false\nadmin_listener:\n  enabled: true\n  address: 127.0.0.1:9090\ntls:\n  mode: acme\n  hostname: proxy.example.com\nresolver:\n  mode: system\npublic_self_ipv4s: []\nper_device_capacity: 64\nabsolute_tunnel_lifetime: disabled\ngraceful_shutdown_drain: 20s\ndestination:\n  profile: code\n  exact_hosts: []\n  suffixes: []\n  dangerous_custom_suffixes: false\nlogging:\n  sink: default\n  sensitive_metadata: false\nmetrics:\n  enabled: false\n", hex.EncodeToString(instanceID[:]), strconv.Quote(stateRoot)))
}
