// Package unifi is the plugin for a UniFi Network console: on a timer it
// asks the console for its devices, the gateway, the switches and the
// access points, for the clients it sees and for its own verdict on its
// subsystems, and writes what the console knows of each as metrics.
//
// It reads and never writes: three GETs per interval, with an API key the
// console minted.
package unifi

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
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

// stands is how many intervals the plugin stands by the names it told: a
// console that misses a read or two does not unname the house, and one
// that is gone does not name it for long, since an address is leased and
// goes to another host in time.
const stands = 5

var (
	errNoHost        = errors.New("--unifi.host is empty")
	errNoFingerprint = errors.New("--unifi.fingerprint is empty")
	errNoKey         = errors.New(keyVar + " is empty")
	errNoInterval    = errors.New("--unifi.interval is not above zero")
	errNoMetrics     = errors.New("it writes metrics and --metrics-url is empty")
	errNoDevices     = errors.New("the console's library knows no device list")
)

// Plugin polls one console.
type Plugin struct {
	host        string
	site        string
	fingerprint string
	interval    time.Duration
}

// New returns the plugin, to be configured by its flags.
func New() *Plugin { return &Plugin{} }

// Name is "unifi".
func (*Plugin) Name() string { return name }

// Flags adds the console's host, site, certificate and polling
// interval. The API key comes from UNIFI_API_KEY.
func (p *Plugin) Flags(set *flag.FlagSet) {
	set.StringVar(
		&p.host,
		"unifi.host",
		"",
		"the console: its name or address, and its port when not 443; https always",
	)
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
	case p.host == "":
		return errNoHost
	case p.fingerprint == "":
		return errNoFingerprint
	case key == "":
		return errNoKey
	case p.interval <= 0:
		return errNoInterval
	}

	// A host and never a URL: the key goes out in a header of the first
	// request, and the pinned certificate guards nothing on a connection
	// that has none.
	origin, err := plugin.HTTPS(p.host)
	if err != nil {
		return fmt.Errorf("--unifi.host: %w", err)
	}

	httpClient, err := console.HTTPClient(p.fingerprint, false, timeout)
	if err != nil {
		return fmt.Errorf("--unifi.fingerprint: %w", err)
	}

	client, err := console.New(httpClient, origin, key, p.site)
	if err != nil {
		return fmt.Errorf("--unifi.host: %w", err)
	}

	devices, err := deviceList()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		poll(ctx, out, client, devices, p.interval)

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
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
// not. The three reads are one: a console that gives its devices and not
// its clients is written as not read, rather than as a house with none.
// What it read also tells the other plugins who each address is; a read
// that failed tells nothing, and the names of the last one stand until
// their time.
func poll(
	ctx context.Context,
	out plugin.Output,
	client *console.Client,
	devices console.Kind,
	interval time.Duration,
) {
	now := time.Now()

	var written []plugin.Sample

	read, err := report(ctx, client, devices)

	switch {
	case ctx.Err() != nil:
		return
	case err != nil:
		slog.WarnContext(ctx, "the console was not read", "plugin", name, "error", err)

		written = []plugin.Sample{{Name: "unifi_up", Value: 0, Time: now}}
	default:
		written = samples(read, now)

		announce(out.Names, read, now, interval)
	}

	if err := out.Metrics.Write(ctx, written); err != nil && ctx.Err() == nil {
		slog.WarnContext(ctx, "the console's metrics were not stored and are lost", "plugin", name, "error", err)
	}
}

// reading is what one read of the console gives: its devices, the clients
// it sees, and its verdict on each of its subsystems.
type reading struct {
	devices []console.Document
	clients []console.Document
	health  []console.Document
}

// report asks the console for the three.
func report(ctx context.Context, client *console.Client, devices console.Kind) (reading, error) {
	var (
		read reading
		err  error
	)

	if read.devices, err = client.List(ctx, devices); err != nil {
		return reading{}, fmt.Errorf("its devices: %w", err)
	}

	if read.clients, err = client.Clients(ctx); err != nil {
		return reading{}, fmt.Errorf("its clients: %w", err)
	}

	if read.health, err = client.Health(ctx); err != nil {
		return reading{}, fmt.Errorf("its health: %w", err)
	}

	return read, nil
}

// announce tells names who each address of a reading made at now is, good for
// stands of the intervals the console is read at.
func announce(names *plugin.Names, read reading, now time.Time, interval time.Duration) {
	names.Tell(name, whoIsWhere(read), now.Add(stands*interval))
}

// whoIsWhere is who each address of the reading is: a device or a client,
// under the name its series carry. An address two of them hold is nobody's:
// the console keeps a client it saw last on an address another has since
// been given, and naming the wrong one is worse than naming none.
func whoIsWhere(read reading) map[netip.Addr]string {
	var (
		called = make(map[netip.Addr]string, len(read.devices)+len(read.clients))
		shared = make(map[netip.Addr]bool)
	)

	hold := func(docs []console.Document, names []string) {
		for index, doc := range docs {
			address, err := netip.ParseAddr(text(doc["ip"]))
			if err != nil || address.IsUnspecified() {
				continue
			}

			address = address.Unmap()

			if _, held := called[address]; held {
				shared[address] = true
			}

			called[address] = names[index]
		}
	}

	hold(read.devices, names(read.devices, "name"))
	hold(read.clients, names(read.clients, "name", "hostname"))

	for address := range shared {
		delete(called, address)
	}

	return called
}
