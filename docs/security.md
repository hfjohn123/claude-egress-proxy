# Security and privacy boundary

This service authenticates a bearer at a shared public edge. It cannot prove
which person uses a credential, and it cannot stop a client from making a direct
connection elsewhere. It is not a traffic-enforcement product.

The server observes client and server IP addresses, destination host and port,
byte sizes, timing, outer TLS metadata, DNS activity, and ACME certificate
transparency exposure. Closed log and metric schemas define what is recorded;
enabling sensitive metadata increases what operators can see. It does not
inspect tunnel payload bytes after CONNECT.

Destination policy, A-record resolution, IPv4 TCP dialing, port 443-only
CONNECT, and rejection of private/reserved destinations are SSRF controls. They
do not make arbitrary client software safe. Unsupported paths include TLS
interception, ordinary HTTP forwarding, SOCKS/UDP/QUIC, HTTP/2 outer proxying,
and IPv6 origin dialing.

Keep configuration and state roots owner-restricted. Never expose the admin
listener, an insecure loopback mode, or credential-bearing URLs on a WAN
interface. Rotate credentials and the admin token after personnel or device
changes.

Backups may restore old credential and token state. After every checkpoint restore,
mandatory rotation is required for all credentials and the admin token;
do not treat restore as a safe rollback. Test restoration in an isolated copy
first and preserve the rotation audit record.
