package config

import (
	"net"
	"strconv"
)

// validateMetricsListen checks server.metrics_listen: the optional address
// of the Prometheus metrics listener. It must be a host:port of its own;
// metrics are never served on server.listen, which may be reachable by
// every user.
func (c *Config) validateMetricsListen(add func(string, ...any)) {
	addr := c.Server.MetricsListen
	if addr == "" {
		return
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		add("server.metrics_listen: must be host:port (e.g. 127.0.0.1:9090)")
		return
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		add("server.metrics_listen: port must be a number between 1 and 65535")
		return
	}
	if sameListenAddress(addr, c.Server.Listen) {
		add("server.metrics_listen: must differ from server.listen (metrics are served on a separate listener)")
		return
	}
	if !isLoopbackHost(host) {
		c.warn("server.metrics_listen: %s is not a loopback address; /metrics has no authentication, so restrict who can reach it (firewall, network policy)", addr)
	}
}

// sameListenAddress reports whether two listen addresses would conflict:
// the same port on the same host, or on the wildcard address.
func sameListenAddress(a, b string) bool {
	ha, pa, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	hb, pb, err := net.SplitHostPort(b)
	if err != nil || pa != pb {
		return false
	}
	wildcard := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	return ha == hb || wildcard(ha) || wildcard(hb)
}
