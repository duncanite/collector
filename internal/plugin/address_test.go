package plugin_test

import (
	"errors"
	"testing"

	"github.com/duncanite/collector/internal/plugin"
)

func TestAHostIsReachedOverHTTPSAndNothingElseIsAHost(t *testing.T) {
	t.Parallel()

	for host, want := range map[string]string{
		"console.example":      "https://console.example",
		"console.example:8443": "https://console.example:8443",
		"192.0.2.1":            "https://192.0.2.1",
		"192.0.2.1:8443":       "https://192.0.2.1:8443",
		"[2001:db8::1]":        "https://[2001:db8::1]",
		"[2001:db8::1]:8443":   "https://[2001:db8::1]:8443",
	} {
		got, err := plugin.HTTPS(host)
		if err != nil || got != want {
			t.Errorf("HTTPS(%q) = %q, %v; want %q", host, got, err, want)
		}
	}

	for _, address := range []string{
		"", "http://console.example", "https://console.example", "HTTP://console.example", "//console.example",
		"console.example/", "console.example/proxy", "console.example?x=1", "console.example#top",
		"someone@console.example", "someone:secret@console.example", " console.example", "console.example ",
		"console.example:port", ":8443", "http:console.example",
	} {
		if got, err := plugin.HTTPS(address); !errors.Is(err, plugin.ErrNotHost) {
			t.Errorf("HTTPS(%q) = %q, %v; want %v", address, got, err, plugin.ErrNotHost)
		}
	}
}
