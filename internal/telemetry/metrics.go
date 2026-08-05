package telemetry

import (
	"errors"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"github.com/prometheus/client_golang/prometheus"
	"math"
	"sync/atomic"
	"time"
)

var ErrInvalidMetrics = errors.New("telemetry: invalid metrics")

const invalidClosed = "telemetry: invalid closed value"

type StateSnapshot struct {
	TLSHandshakeLimiterEntries, AuthenticationLimiterEntries, PACLimiterEntries, PreAuthConnections, PendingSetupReservations, ActiveTunnels, CredentialGeneration uint64
	Ready                                                                                                                                                          bool
}
type Metrics struct {
	registry                                                          *prometheus.Registry
	clock                                                             timebase.Clock
	certificateNotAfter                                               func() (time.Time, bool)
	state                                                             atomic.Pointer[StateSnapshot]
	stateMetrics                                                      prometheus.Collector
	tls, auth, connect, closes, pac, limiter, reload, delivery, bytes *prometheus.CounterVec
	setup, tunnel                                                     *prometheus.HistogramVec
}

func NewMetrics(clock timebase.Clock, cert func() (time.Time, bool)) (*Metrics, error) {
	if clock == nil || cert == nil {
		return nil, ErrInvalidMetrics
	}
	m := &Metrics{registry: prometheus.NewPedanticRegistry(), clock: clock, certificateNotAfter: cert}
	m.state.Store(&StateSnapshot{})
	m.stateMetrics = &stateCollector{metrics: m,
		limiterEntries:       prometheus.NewDesc("claude_proxy_limiter_entries", "Current tracked limiter entries by limiter.", []string{"limiter"}, nil),
		preAuth:              prometheus.NewDesc("claude_proxy_pre_auth_connections", "Current admitted pre-authentication connections.", nil, nil),
		pendingSetup:         prometheus.NewDesc("claude_proxy_pending_setup_reservations", "Current authenticated pending setup reservations.", nil, nil),
		activeTunnels:        prometheus.NewDesc("claude_proxy_active_tunnels", "Current established tunnels.", nil, nil),
		credentialGeneration: prometheus.NewDesc("claude_proxy_credential_generation", "Current installed credential generation, or zero when unavailable.", nil, nil),
	}
	m.tls = cv("claude_proxy_tls_handshakes_total")
	m.auth = cv("claude_proxy_authentication_total")
	m.connect = cv("claude_proxy_connect_total")
	m.closes = cv("claude_proxy_tunnel_closes_total")
	m.pac = cv("claude_proxy_pac_total")
	m.limiter = cv("claude_proxy_limiter_events_total")
	m.reload = cv("claude_proxy_reload_total")
	m.delivery = cv("claude_proxy_log_records_total")
	m.bytes = cv("claude_proxy_bytes_total")
	m.setup = hv("claude_proxy_setup_duration_seconds")
	m.tunnel = hv("claude_proxy_tunnel_duration_seconds")
	for _, c := range []prometheus.Collector{m.tls, m.auth, m.connect, m.closes, m.pac, m.limiter, m.reload, m.delivery, m.bytes, m.setup, m.tunnel} {
		if err := m.registry.Register(c); err != nil {
			return nil, ErrInvalidMetrics
		}
	}
	if err := m.registry.Register(m.stateMetrics); err != nil {
		return nil, ErrInvalidMetrics
	}
	for _, v := range contract.AllTLSResults() {
		m.tls.WithLabelValues(v)
	}
	for _, v := range contract.AllAuthenticationResults() {
		m.auth.WithLabelValues(v)
	}
	for _, v := range contract.AllConnectResults() {
		m.connect.WithLabelValues(v)
	}
	for _, v := range contract.AllCloseResults() {
		m.closes.WithLabelValues(v)
	}
	for _, v := range contract.AllPACResults() {
		m.pac.WithLabelValues(v)
	}
	for _, k := range contract.AllReloadKinds() {
		for _, r := range contract.AllReloadResults() {
			m.reload.WithLabelValues(k, r)
		}
	}
	for _, v := range contract.AllDeliveryResults() {
		m.delivery.WithLabelValues(v)
	}
	for _, v := range []string{"client_to_origin", "origin_to_client"} {
		m.bytes.WithLabelValues(v)
	}
	for _, v := range contract.AllSetupOutcomes() {
		m.setup.WithLabelValues(v)
	}
	for _, v := range contract.AllTunnelOutcomes() {
		m.tunnel.WithLabelValues(v)
	}
	for _, l := range contract.AllLimiters() {
		for _, e := range contract.AllLimiterEvents() {
			if ValidLimiterPairs[l+"/"+e] {
				m.limiter.WithLabelValues(l, e)
			}
		}
	}
	for name, fn := range map[string]func() float64{"claude_proxy_certificate_expiry_seconds": func() float64 {
		n, ok := m.certificateNotAfter()
		now := m.clock.Now().UTC()
		if !ok {
			return 0
		}
		d := n.Sub(now)
		if d < 0 {
			return 0
		}
		return math.Floor(d.Seconds())
	}} {
		m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: "Seconds until the active certificate expires, floored at zero."}, fn))
	}
	return m, nil
}

type stateCollector struct {
	metrics                                                                    *Metrics
	limiterEntries, preAuth, pendingSetup, activeTunnels, credentialGeneration *prometheus.Desc
}

func (c *stateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.limiterEntries
	ch <- c.preAuth
	ch <- c.pendingSetup
	ch <- c.activeTunnels
	ch <- c.credentialGeneration
}

func (c *stateCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.metrics.state.Load()
	ch <- prometheus.MustNewConstMetric(c.limiterEntries, prometheus.GaugeValue, float64(s.TLSHandshakeLimiterEntries), "tls_handshake")
	ch <- prometheus.MustNewConstMetric(c.limiterEntries, prometheus.GaugeValue, float64(s.AuthenticationLimiterEntries), "authentication")
	ch <- prometheus.MustNewConstMetric(c.limiterEntries, prometheus.GaugeValue, float64(s.PACLimiterEntries), "pac")
	ch <- prometheus.MustNewConstMetric(c.preAuth, prometheus.GaugeValue, float64(s.PreAuthConnections))
	ch <- prometheus.MustNewConstMetric(c.pendingSetup, prometheus.GaugeValue, float64(s.PendingSetupReservations))
	ch <- prometheus.MustNewConstMetric(c.activeTunnels, prometheus.GaugeValue, float64(s.ActiveTunnels))
	ch <- prometheus.MustNewConstMetric(c.credentialGeneration, prometheus.GaugeValue, float64(s.CredentialGeneration))
}
func metricDefinition(name string) MetricDefinition {
	for _, definition := range MetricDefinitions {
		if definition.Name == name {
			return definition
		}
	}
	panic("telemetry: missing generated metric definition")
}
func cv(name string) *prometheus.CounterVec {
	d := metricDefinition(name)
	return prometheus.NewCounterVec(prometheus.CounterOpts{Name: d.Name, Help: d.Help}, d.Labels)
}
func hv(name string) *prometheus.HistogramVec {
	d := metricDefinition(name)
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: d.Name, Help: d.Help, Buckets: d.Buckets}, d.Labels)
}
func (m *Metrics) Gatherer() prometheus.Gatherer { return m.registry }
func (m *Metrics) PublishState(s StateSnapshot) {
	if s.TLSHandshakeLimiterEntries > 1<<53-1 || s.AuthenticationLimiterEntries > 1<<53-1 || s.PACLimiterEntries > 1<<53-1 || s.PreAuthConnections > 1<<53-1 || s.PendingSetupReservations > 1<<53-1 || s.ActiveTunnels > 1<<53-1 || s.CredentialGeneration > 1<<53-1 {
		panic(invalidClosed)
	}
	m.state.Store(&s)
}
func (m *Metrics) IncTLS(v contract.TLSResult) { m.tls.WithLabelValues(validTLS(v)).Inc() }
func (m *Metrics) IncAuthentication(v contract.AuthenticationResult) {
	m.auth.WithLabelValues(validAuth(v)).Inc()
}
func (m *Metrics) IncConnect(v contract.ConnectResult) {
	m.connect.WithLabelValues(validConnect(v)).Inc()
}
func (m *Metrics) IncPAC(v contract.PACResult) { m.pac.WithLabelValues(validPAC(v)).Inc() }
func (m *Metrics) IncLimiter(l contract.Limiter, e contract.LimiterEvent) {
	a := validLimiter(l)
	b := validEvent(e)
	if !ValidLimiterPairs[a+"/"+b] {
		panic(invalidClosed)
	}
	m.limiter.WithLabelValues(a, b).Inc()
}
func (m *Metrics) IncReload(k contract.ReloadKind, r contract.ReloadResult) {
	m.reload.WithLabelValues(validKind(k), validResult(r)).Inc()
}
func (m *Metrics) ObserveSetup(o contract.SetupOutcome, d time.Duration) {
	if d < 0 {
		panic(invalidClosed)
	}
	m.setup.WithLabelValues(validSetup(o)).Observe(d.Seconds())
}
func (m *Metrics) FinishTunnel(c contract.CloseResult, o contract.TunnelOutcome, d time.Duration, b contract.ByteTotals) {
	if d < 0 || !validCloseResult(c) || !validTunnelOutcome(o) || b.ClientToOrigin > 1<<53-1 || b.OriginToClient > 1<<53-1 || contract.TunnelOutcomeForCloseResult(c) != o {
		panic(invalidClosed)
	}
	m.closes.WithLabelValues(validClose(c)).Inc()
	m.tunnel.WithLabelValues(validTunnel(o)).Observe(d.Seconds())
	m.bytes.WithLabelValues("client_to_origin").Add(float64(b.ClientToOrigin))
	m.bytes.WithLabelValues("origin_to_client").Add(float64(b.OriginToClient))
}
func (m *Metrics) RecordDelivery(v contract.DeliveryResult) {
	m.delivery.WithLabelValues(validDelivery(v)).Inc()
}
func validTLS(v contract.TLSResult) string {
	return enum(func() string { return v.String() }, contract.ParseTLSResult)
}
func validAuth(v contract.AuthenticationResult) string {
	return enum(func() string { return v.String() }, contract.ParseAuthenticationResult)
}
func validConnect(v contract.ConnectResult) string {
	return enum(func() string { return v.String() }, contract.ParseConnectResult)
}
func validPAC(v contract.PACResult) string {
	return enum(func() string { return v.String() }, contract.ParsePACResult)
}
func validLimiter(v contract.Limiter) string {
	return enum(func() string { return v.String() }, contract.ParseLimiter)
}
func validEvent(v contract.LimiterEvent) string {
	return enum(func() string { return v.String() }, contract.ParseLimiterEvent)
}
func validKind(v contract.ReloadKind) string {
	return enum(func() string { return v.String() }, contract.ParseReloadKind)
}
func validResult(v contract.ReloadResult) string {
	return enum(func() string { return v.String() }, contract.ParseReloadResult)
}
func validSetup(v contract.SetupOutcome) string {
	return enum(func() string { return v.String() }, contract.ParseSetupOutcome)
}
func validTunnel(v contract.TunnelOutcome) string {
	return enum(func() string { return v.String() }, contract.ParseTunnelOutcome)
}
func validTunnelOutcome(v contract.TunnelOutcome) bool {
	_, ok := contract.ParseTunnelOutcome(safeString(func() string { return v.String() }))
	return ok
}
func validCloseResult(v contract.CloseResult) bool {
	_, ok := contract.ParseCloseResult(safeString(func() string { return v.String() }))
	return ok
}
func validClose(v contract.CloseResult) string {
	return enum(func() string { return v.String() }, contract.ParseCloseResult)
}
func validDelivery(v contract.DeliveryResult) string {
	return enum(func() string { return v.String() }, contract.ParseDeliveryResult)
}
func enum[T any](f func() string, p func(string) (T, bool)) string {
	s := safeString(f)
	if _, ok := p(s); !ok {
		panic(invalidClosed)
	}
	return s
}
