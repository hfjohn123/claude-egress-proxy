package config

import (
	"net/netip"
	"time"
)

type ValidationMode uint8

const (
	ValidationInvalid ValidationMode = iota
	ValidatePure
	ValidateOperational
	ValidatePreServe
)

type TLSMode uint8

const (
	TLSInvalid TLSMode = iota
	TLSACME
	TLSSupplied
	TLSInsecureLoopback
)

type ResolverMode uint8

const (
	ResolverInvalid ResolverMode = iota
	ResolverSystem
	ResolverExplicit
)

type Profile uint8

const (
	ProfileInvalid Profile = iota
	ProfileCode
	ProfileWebDesktop
	ProfileAll
)

type LogSink uint8

const (
	LogSinkInvalid LogSink = iota
	LogSinkDefault
	LogSinkFile
)

type Config struct {
	formatVersion                 uint32
	instanceID                    [16]byte
	stateRoot                     string
	publicListener                PublicListener
	adminListener                 AdminListener
	tls                           TLS
	resolver                      Resolver
	outboundSource                netip.Addr
	publicSelf                    []netip.Addr
	perDeviceCapacity             uint32
	absoluteTunnelLifetime        time.Duration
	absoluteTunnelLifetimeEnabled bool
	gracefulShutdownDrain         time.Duration
	destination                   Destination
	logging                       Logging
	metrics                       Metrics
}
type PublicListener struct {
	addresses  []netip.AddrPort
	pacEnabled bool
}
type AdminListener struct {
	enabled    bool
	address    netip.AddrPort
	hasAddress bool
}
type TLS struct {
	mode                                      TLSMode
	hostname, certificateFile, privateKeyFile string
}
type Resolver struct {
	mode       ResolverMode
	address    netip.AddrPort
	hasAddress bool
}
type Destination struct {
	profile                 Profile
	exactHosts, suffixes    []string
	dangerousCustomSuffixes bool
}
type Logging struct {
	sink              LogSink
	filePath          string
	sensitiveMetadata bool
}
type Metrics struct{ enabled bool }

func (c Config) FormatVersion() uint32 { return c.formatVersion }
func (c Config) InstanceID() [16]byte  { return c.instanceID }
func (c Config) StateRootPath() string { return c.stateRoot }
func (c Config) PublicListener() PublicListener {
	c.publicListener.addresses = append([]netip.AddrPort(nil), c.publicListener.addresses...)
	return c.publicListener
}
func (c Config) AdminListener() AdminListener { return c.adminListener }
func (c Config) TLS() TLS                     { return c.tls }
func (c Config) Resolver() Resolver           { return c.resolver }
func (c Config) OutboundSourceIPv4() (netip.Addr, bool) {
	return c.outboundSource, c.outboundSource.IsValid()
}
func (c Config) PublicSelfIPv4s() []netip.Addr { return append([]netip.Addr(nil), c.publicSelf...) }
func (c Config) PerDeviceCapacity() uint32     { return c.perDeviceCapacity }
func (c Config) AbsoluteTunnelLifetime() (time.Duration, bool) {
	return c.absoluteTunnelLifetime, c.absoluteTunnelLifetimeEnabled
}
func (c Config) GracefulShutdownDrain() time.Duration { return c.gracefulShutdownDrain }
func (c Config) Destination() Destination {
	c.destination.exactHosts = append([]string(nil), c.destination.exactHosts...)
	c.destination.suffixes = append([]string(nil), c.destination.suffixes...)
	return c.destination
}
func (c Config) Logging() Logging { return c.logging }
func (c Config) Metrics() Metrics { return c.metrics }
func (p PublicListener) Addresses() []netip.AddrPort {
	return append([]netip.AddrPort(nil), p.addresses...)
}
func (p PublicListener) PACEnabled() bool               { return p.pacEnabled }
func (a AdminListener) Enabled() bool                   { return a.enabled }
func (a AdminListener) Address() (netip.AddrPort, bool) { return a.address, a.hasAddress }
func (t TLS) Mode() TLSMode                             { return t.mode }
func (t TLS) Hostname() string                          { return t.hostname }
func (t TLS) CertificateFile() string                   { return t.certificateFile }
func (t TLS) PrivateKeyFile() string                    { return t.privateKeyFile }
func (r Resolver) Mode() ResolverMode                   { return r.mode }
func (r Resolver) Address() (netip.AddrPort, bool)      { return r.address, r.hasAddress }
func (d Destination) Profile() Profile                  { return d.profile }
func (d Destination) ExactHosts() []string              { return append([]string(nil), d.exactHosts...) }
func (d Destination) Suffixes() []string                { return append([]string(nil), d.suffixes...) }
func (d Destination) DangerousCustomSuffixes() bool     { return d.dangerousCustomSuffixes }
func (l Logging) Sink() LogSink                         { return l.sink }
func (l Logging) FilePath() string                      { return l.filePath }
func (l Logging) SensitiveMetadata() bool               { return l.sensitiveMetadata }
func (m Metrics) Enabled() bool                         { return m.enabled }

func cloneConfig(c Config) Config {
	c.publicListener.addresses = append([]netip.AddrPort(nil), c.publicListener.addresses...)
	c.publicSelf = append([]netip.Addr(nil), c.publicSelf...)
	c.destination.exactHosts = append([]string(nil), c.destination.exactHosts...)
	c.destination.suffixes = append([]string(nil), c.destination.suffixes...)
	return c
}
