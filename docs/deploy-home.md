# Home deployment

Home deployment needs an Internet-reachable TCP 443 path to the server. Configure
the router's TCP 443 forwarding and the host firewall, then verify externally;
LAN success alone is not evidence of public reachability. TLS-ALPN-01 needs the
same reachability.

DDNS can preserve a name across WAN address changes, but it does not provide a
stable egress IP. CGNAT, ISP filtering, changing WAN addresses, and port-443
blocking can make a home service unsuitable. A VPS is usually a better fit when
stable egress or reliable inbound reachability matters.

Behind NAT, configure `public_self_ipv4s` from externally verified addresses so
the service does not connect back to its own public listener. Recheck after WAN
changes. IPv6 exposure is opt-in: opening an IPv6 firewall can expose a service
without a router-forwarding rule, while origin connections remain IPv4-only.

Use supplied certificates or ACME only after public DNS and TLS-ALPN-01 reach
the host. Never bind an insecure loopback mode or the admin listener to a WAN
address. Rotate credentials after testing with any disposable device.
