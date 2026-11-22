// Package unifisyslog is the plugin for UniFi's remote syslog: it listens
// on UDP for the lines the gateway, the access points, the switch and the
// console send, reads each into a record, and writes it to the logs store.
//
// The lines come over plain UDP with nothing to say who sent them: the
// sender's address is kept on every record, and nothing in a line is
// trusted. Who the two ends of a firewall line are is asked of the
// collector's own names, by the addresses the line gives.
package unifisyslog

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"time"
	_ "time/tzdata" // the zones --unifi-syslog.location names, compiled in: an image from scratch has none

	"github.com/duncanite/collector/internal/plugin"
)

// name is what a deployment enables the plugin by.
const name = "unifi-syslog"

// largest is more than any datagram can carry.
const largest = 65536

var (
	errNoListen = errors.New("--unifi-syslog.listen is empty")
	errNoLogs   = errors.New("it writes logs and --logs-url is empty")
)

// Plugin listens on one UDP address.
type Plugin struct {
	listen   string
	location string
}

// New returns the plugin, to be configured by its flags.
func New() *Plugin { return &Plugin{} }

// Name is "unifi-syslog".
func (*Plugin) Name() string { return name }

// Flags adds the address to listen on and the senders' time zone.
func (p *Plugin) Flags(set *flag.FlagSet) {
	set.StringVar(&p.listen, "unifi-syslog.listen", "", "the UDP address the devices send to: host:port, or :port")
	set.StringVar(&p.location, "unifi-syslog.location", "UTC",
		"the devices' time zone, an IANA name: their timestamps carry none")
}

// Run reads datagrams until ctx ends. Each is one line, written to the
// store at once, alone: a line the store refuses is logged here and lost,
// and while the store is slow the lines that arrive wait in the socket's
// buffer, and are dropped by the kernel once it is full.
func (p *Plugin) Run(ctx context.Context, out plugin.Output) error {
	switch {
	case out.Logs == nil:
		return errNoLogs
	case p.listen == "":
		return errNoListen
	}

	location, err := time.LoadLocation(p.location)
	if err != nil {
		return fmt.Errorf("--unifi-syslog.location: %w", err)
	}

	var config net.ListenConfig

	conn, err := config.ListenPacket(ctx, "udp", p.listen)
	if err != nil {
		return fmt.Errorf("--unifi-syslog.listen: %w", err)
	}

	// Closing the socket is what ends a read that waits.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	buffer := make([]byte, largest)

	for {
		size, sender, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return fmt.Errorf("reading from %s: %w", p.listen, err)
		}

		now := time.Now()
		record := Named(Parse(buffer[:size], address(sender), now, location), out.Names, now)

		if err := out.Logs.Write(ctx, []plugin.Record{record}); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "a line was not stored and is lost", "plugin", name, "error", err)
		}
	}
}

// address is a sender's address without its port.
func address(sender net.Addr) string {
	if udp, ok := sender.(*net.UDPAddr); ok {
		return udp.IP.String()
	}

	return sender.String()
}
