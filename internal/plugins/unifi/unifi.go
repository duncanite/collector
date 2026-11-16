// Package unifi is the plugin for a UniFi Network console: on a timer it
// asks the console for its devices, the gateway, the switches and the
// access points, and writes what the console knows of each as metrics.
//
// It reads and never writes: one GET of the device list per interval, with
// an API key the console minted.
package unifi

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/duncanite/go-unifi/console"

	"github.com/duncanite/collector/internal/plugin"
)

// name is what a deployment enables the plugin by.
const name = "unifi"

// keyVar holds the console's API key; it is never a flag, so never in a
// process list or a container's arguments.
const keyVar = "UNIFI_API_KEY" // #nosec G101 -- the variable's name, not a credential

// timeout bounds one read of the console; it answers the device list in
// well under a second.
const timeout = 30 * time.Second

var (
	errNoURL    = errors.New("--unifi.url is empty")
	errNotHTTPS = errors.New(
		"--unifi.url is not an https address: the API key would cross the network in the clear",
	)
	errNoFingerprint = errors.New("--unifi.fingerprint is empty")
	errNoKey         = errors.New(keyVar + " is empty")
	errNoInterval    = errors.New("--unifi.interval is not above zero")
	errNoMetrics     = errors.New("it writes metrics and --metrics-url is empty")
	errNoDevices     = errors.New("the console's library knows no device list")
)

// Plugin polls one console.
type Plugin struct {
	url         string
	site        string
	fingerprint string
	interval    time.Duration
}

// New returns the plugin, to be configured by its flags.
func New() *Plugin { return &Plugin{} }

// Name is "unifi".
func (*Plugin) Name() string { return name }

// Flags adds the console's address, site, certificate and polling
// interval. The API key comes from UNIFI_API_KEY.
func (p *Plugin) Flags(set *flag.FlagSet) {
	set.StringVar(&p.url, "unifi.url", "", "the console: scheme and host")
	set.StringVar(&p.site, "unifi.site", console.DefaultSite, "the Network site")
	set.StringVar(&p.fingerprint, "unifi.fingerprint", "",
		"SHA-256 of the console's certificate, hex, pinned in place of the system roots")
	set.DurationVar(&p.interval, "unifi.interval", time.Minute, "how often the console is read")
}

// Run reads the console now and then every interval, until ctx ends. A
// read that fails is logged and written as unifi_up 0; the next one comes
// at its time, none is tried again sooner.
func (p *Plugin) Run(ctx context.Context, out plugin.Output) error {
	key := os.Getenv(keyVar)

	switch {
	case out.Metrics == nil:
		return errNoMetrics
	case p.url == "":
		return errNoURL
	case !encrypted(p.url):
		return errNotHTTPS
	case p.fingerprint == "":
		return errNoFingerprint
	case key == "":
		return errNoKey
	case p.interval <= 0:
		return errNoInterval
	}

	httpClient, err := console.HTTPClient(p.fingerprint, false, timeout)
	if err != nil {
		return fmt.Errorf("--unifi.fingerprint: %w", err)
	}

	client, err := console.New(httpClient, p.url, key, p.site)
	if err != nil {
		return fmt.Errorf("--unifi.url: %w", err)
	}

	devices, err := deviceList()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		poll(ctx, out, client, devices)

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// encrypted reports whether address is an https one. The key goes out in
// a header of the first request, before any answer could say the console
// is elsewhere, and the pinned certificate guards nothing on a connection
// that has none.
func encrypted(address string) bool {
	parsed, err := url.Parse(address)
	if err != nil || parsed == nil {
		return false
	}

	return parsed.Scheme == "https" && parsed.Host != ""
}

// deviceList is the kind the console's library lists the devices by.
func deviceList() (console.Kind, error) {
	for _, kind := range console.Kinds() {
		if kind.Name == console.Device {
			return kind, nil
		}
	}

	return console.Kind{}, errNoDevices
}

// poll reads the console once and writes what it read, or that it could
// not.
func poll(ctx context.Context, out plugin.Output, client *console.Client, devices console.Kind) {
	now := time.Now()

	var written []plugin.Sample

	docs, err := client.List(ctx, devices)

	switch {
	case ctx.Err() != nil:
		return
	case err != nil:
		slog.WarnContext(ctx, "the console was not read", "plugin", name, "error", err)

		written = []plugin.Sample{{Name: "unifi_up", Value: 0, Time: now}}
	default:
		written = samples(docs, now)
	}

	if err := out.Metrics.Write(ctx, written); err != nil && ctx.Err() == nil {
		slog.WarnContext(ctx, "the console's metrics were not stored and are lost", "plugin", name, "error", err)
	}
}
