package contract

// Frame identifies one fixed HTTP response frame.
type Frame uint8

const (
	frameBadRequest Frame = iota
	frameForbidden
	frameNotFound
	frameMethodNotAllowedConnect
	frameMethodNotAllowedGet
	frameProxyAuthenticationRequired
	frameTooManyRequests
	frameInternalError
	frameBadGateway
	frameServiceUnavailable
	frameGatewayTimeout
	frameHTTPVersionNotSupported
	frameConnectEstablished
	framePACOK
	frameHealthOK
	frameReadyOK
	frameNotReady
	frameMetricsUnauthorized
	frameMetricsOK
)

var allFrames = []string{
	"bad_request", "forbidden", "not_found", "method_not_allowed_connect", "method_not_allowed_get",
	"proxy_authentication_required", "too_many_requests", "internal_error",
	"bad_gateway", "service_unavailable", "gateway_timeout", "http_version_not_supported", "connect_established",
	"pac_ok", "health_ok", "ready_ok", "not_ready", "metrics_unauthorized", "metrics_ok",
}

// AllFrames returns a copy of every supported frame identifier in wire order.
func AllFrames() []string { return append([]string(nil), allFrames...) }

// ParseFrame returns the closed frame value for value.
func ParseFrame(value string) (Frame, bool) {
	switch value {
	case "bad_request":
		return frameBadRequest, true
	case "forbidden":
		return frameForbidden, true
	case "not_found":
		return frameNotFound, true
	case "method_not_allowed_connect":
		return frameMethodNotAllowedConnect, true
	case "method_not_allowed_get":
		return frameMethodNotAllowedGet, true
	case "proxy_authentication_required":
		return frameProxyAuthenticationRequired, true
	case "too_many_requests":
		return frameTooManyRequests, true
	case "internal_error":
		return frameInternalError, true
	case "bad_gateway":
		return frameBadGateway, true
	case "service_unavailable":
		return frameServiceUnavailable, true
	case "gateway_timeout":
		return frameGatewayTimeout, true
	case "http_version_not_supported":
		return frameHTTPVersionNotSupported, true
	case "connect_established":
		return frameConnectEstablished, true
	case "pac_ok":
		return framePACOK, true
	case "health_ok":
		return frameHealthOK, true
	case "ready_ok":
		return frameReadyOK, true
	case "not_ready":
		return frameNotReady, true
	case "metrics_unauthorized":
		return frameMetricsUnauthorized, true
	case "metrics_ok":
		return frameMetricsOK, true
	default:
		return 0, false
	}
}

func (f Frame) String() string {
	switch f {
	case frameBadRequest:
		return "bad_request"
	case frameForbidden:
		return "forbidden"
	case frameNotFound:
		return "not_found"
	case frameMethodNotAllowedConnect:
		return "method_not_allowed_connect"
	case frameMethodNotAllowedGet:
		return "method_not_allowed_get"
	case frameProxyAuthenticationRequired:
		return "proxy_authentication_required"
	case frameTooManyRequests:
		return "too_many_requests"
	case frameInternalError:
		return "internal_error"
	case frameBadGateway:
		return "bad_gateway"
	case frameServiceUnavailable:
		return "service_unavailable"
	case frameGatewayTimeout:
		return "gateway_timeout"
	case frameHTTPVersionNotSupported:
		return "http_version_not_supported"
	case frameConnectEstablished:
		return "connect_established"
	case framePACOK:
		return "pac_ok"
	case frameHealthOK:
		return "health_ok"
	case frameReadyOK:
		return "ready_ok"
	case frameNotReady:
		return "not_ready"
	case frameMetricsUnauthorized:
		return "metrics_unauthorized"
	case frameMetricsOK:
		return "metrics_ok"
	default:
		panic("invalid frame")
	}
}
