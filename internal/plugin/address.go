package plugin

import (
	"errors"
	"net/url"
	"strings"
)

// ErrNotHost is an address that is more, or less, than a host.
var ErrNotHost = errors.New("not a host, or a host and a port: the scheme is always https and is not given")

// HTTPS is the https origin of host, a name or an address with or without
// a port. A plugin that carries a credential takes a host and never a URL:
// there is then no way to write an address that sends the credential in
// the clear.
func HTTPS(host string) (string, error) {
	if host == "" || strings.ContainsAny(host, "/?#@ \t") {
		return "", ErrNotHost
	}

	origin := "https://" + host

	parsed, err := url.Parse(origin)
	if err != nil || parsed == nil || parsed.Host != host || parsed.Hostname() == "" {
		return "", ErrNotHost
	}

	return origin, nil
}
