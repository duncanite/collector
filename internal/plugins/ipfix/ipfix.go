// Package ipfix is the plugin for IPFIX, the flow export a gateway calls
// NetFlow version 10: it listens on UDP for the messages an exporter
// sends, reads each flow into a record, what went from where to where and
// how much of it, and writes the records to the logs store.
//
// The messages come over plain UDP with nothing to say who sent them: the
// sender's address is kept on every record, and nothing in a message is
// trusted.
package ipfix

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/duncanite/collector/internal/plugin"
)

// name is what a deployment enables the plugin by.
const name = "ipfix"

// largest is more than any datagram can carry.
const largest = 65536

// quiet is the least time between two warnings of datagrams that were not
// read: whoever sends them does not get to write the collector's own log
// at their pace.
const quiet = time.Minute

var (
	errNoListen = errors.New("--ipfix.listen is empty")
	errNoLogs   = errors.New("it writes logs and --logs-url is empty")
)

// Plugin listens on one UDP address.
type Plugin struct {
	listen string
}

// New returns the plugin, to be configured by its flags.
func New() *Plugin { return &Plugin{} }

// Name is "ipfix".
func (*Plugin) Name() string { return name }

// Flags adds the address to listen on.
func (p *Plugin) Flags(set *flag.FlagSet) {
	set.StringVar(&p.listen, "ipfix.listen", "", "the UDP address the exporters send to: host:port, or :port")
}

// Run reads datagrams until ctx ends. The flows of one are written to the
// store at once, in one request: those the store refuses are logged here
// and lost, and while the store is slow the datagrams that arrive wait in
// the socket's buffer, and are dropped by the kernel once it is full.
func (p *Plugin) Run(ctx context.Context, out plugin.Output) error {
	switch {
	case out.Logs == nil:
		return errNoLogs
	case p.listen == "":
		return errNoListen
	}

	var config net.ListenConfig

	conn, err := config.ListenPacket(ctx, "udp", p.listen)
	if err != nil {
		return fmt.Errorf("--ipfix.listen: %w", err)
	}

	// Closing the socket is what ends a read that waits.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	var (
		reader = NewReader()
		buffer = make([]byte, largest)
		missed unread
	)

	reader.Name(out.Names)

	for {
		size, sender, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return fmt.Errorf("reading from %s: %w", p.listen, err)
		}

		records, err := reader.Read(buffer[:size], exporter(sender), time.Now())
		if err != nil {
			missed.note(ctx, err)
		}

		if len(records) == 0 {
			continue
		}

		if err := out.Logs.Write(ctx, records); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "flows were not stored and are lost",
				"plugin", name, "flows", len(records), "error", err)
		}
	}
}

// exporter is a sender's address and port: what its templates are its own
// by.
func exporter(sender net.Addr) netip.AddrPort {
	if udp, ok := sender.(*net.UDPAddr); ok {
		return udp.AddrPort()
	}

	return netip.AddrPort{}
}

// unread counts the datagrams that were not read whole, and says so at
// most once every quiet: the first at once, the others by their number.
type unread struct {
	count int
	told  time.Time
}

func (u *unread) note(ctx context.Context, err error) {
	u.count++

	now := time.Now()
	if now.Sub(u.told) < quiet {
		return
	}

	slog.WarnContext(ctx, "datagrams were not read whole", "plugin", name, "datagrams", u.count, "last", err)

	u.count, u.told = 0, now
}
