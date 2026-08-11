package cli

var (
	UsageRoot             = []byte("usage: claude-egress-proxy [--config <absolute-file>] <command>\n")
	UsageInit             = []byte("usage: claude-egress-proxy [--config <absolute-file>] init [--state-root <absolute-directory>]\n")
	UsageCredential       = []byte("usage: claude-egress-proxy [--config <absolute-file>] credential <subcommand>\n")
	UsageCredentialAdd    = []byte("usage: claude-egress-proxy [--config <absolute-file>] credential add --device <device-identifier>\n")
	UsageCredentialRevoke = []byte("usage: claude-egress-proxy [--config <absolute-file>] credential revoke --record <record-id>\n")
	UsageCredentialPurge  = []byte("usage: claude-egress-proxy [--config <absolute-file>] credential purge --record <record-id>\n")
	UsageCredentialList   = []byte("usage: claude-egress-proxy [--config <absolute-file>] credential list\n")
	UsageAdminTokenRotate = []byte("usage: claude-egress-proxy [--config <absolute-file>] admin-token rotate\n")
	UsagePAC              = []byte("usage: claude-egress-proxy [--config <absolute-file>] pac --output <absolute-file>\n")
	UsageConfigApply      = []byte("usage: claude-egress-proxy [--config <absolute-installed-file>] config apply --input <absolute-draft-file>\n")
	UsageCheckConfig      = []byte("usage: claude-egress-proxy [--config <absolute-file>] check config\n")
	UsageCheckHealth      = []byte("usage: claude-egress-proxy check health --address <loopback-IP:port>\n")
	UsageCheckNetwork     = []byte("usage: claude-egress-proxy [--config <absolute-file>] check network [--public-ip-url <https-url>]\n")
	UsageService          = []byte("usage: claude-egress-proxy [--config <absolute-file>] service <install|uninstall|start|stop>\n")
	UsageServe            = []byte("usage: claude-egress-proxy [--config <absolute-file>] serve\n")
)

// UsageError is the fixed one-line usage response for an invalid invocation.
type UsageError struct{ Bytes []byte }

func usage(bytes []byte) *UsageError { return &UsageError{Bytes: bytes} }

func usageFor(command Command) *UsageError {
	switch command {
	case Serve:
		return usage(UsageServe)
	case Init:
		return usage(UsageInit)
	case CredentialAdd:
		return usage(UsageCredentialAdd)
	case CredentialRevoke:
		return usage(UsageCredentialRevoke)
	case CredentialPurge:
		return usage(UsageCredentialPurge)
	case CredentialList:
		return usage(UsageCredentialList)
	case AdminTokenRotate:
		return usage(UsageAdminTokenRotate)
	case PAC:
		return usage(UsagePAC)
	case ConfigApply:
		return usage(UsageConfigApply)
	case CheckConfig:
		return usage(UsageCheckConfig)
	case CheckHealth:
		return usage(UsageCheckHealth)
	case CheckNetwork:
		return usage(UsageCheckNetwork)
	case Service:
		return usage(UsageService)
	default:
		return usage(UsageRoot)
	}
}
