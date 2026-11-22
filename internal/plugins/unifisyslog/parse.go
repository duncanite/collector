package unifisyslog

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/duncanite/collector/internal/plugin"
)

// stamp is the timestamp of an RFC 3164 line: no year, no zone.
const stamp = time.Stamp

// day is how far from its reading, before or after, a line may say it
// happened and be believed. A device's clock is the network's, and a line
// comes as it is written: one that claims another day has a clock that is
// wrong, or a sender that is not a device.
const day = 24 * time.Hour

// peer is the field the sender's address is kept under, and what the
// store groups a deployment's lines by: the one thing of a datagram its
// sender does not write.
const peer = "network.peer.address"

// The fields the two ends of a firewall line are written under, the names
// a flow's ends have: one query finds an address, or a host, in both.
const (
	sourceAddress      = "source.address"
	destinationAddress = "destination.address"
	sourceName         = "source.name"
	destinationName    = "destination.name"
)

// The syslog priority: a facility times eight, plus a severity.
const (
	severities = 8
	maxPri     = 191
)

// A line's shapes, as UniFi's devices send them.
var (
	// "<pri>" at the head of a line. The console's CEF events have none.
	priority = regexp.MustCompile(`^<(\d{1,3})>`)
	// An access point's tag: "<mac>,<model>-<firmware>".
	deviceTag = regexp.MustCompile(`^([0-9a-f]{12}),(.+)-(\d[^-]*)$`)
	// "<program>[pid]: text" or "<program>: text"; the text may hold line
	// feeds.
	program = regexp.MustCompile(`(?s)^([A-Za-z0-9_./-]+)(?:\[(\d+)\])?: (.*)$`)
	// The gateway's firewall log, the kernel's own line with no program:
	// "[<chain>-<action>-<rule>] DESCR="<policy>" IN=… OUT=… ".
	firewall  = regexp.MustCompile(`^\[([A-Za-z0-9_-]+)\] DESCR="([^"]*)" IN=([^ ]*) OUT=([^ ]*) `)
	addresses = regexp.MustCompile(` SRC=([^ ]+) DST=([^ ]+) `)
	transport = regexp.MustCompile(` PROTO=([^ ]+)`)
	ports     = regexp.MustCompile(` SPT=(\d+) DPT=(\d+) `)
)

//nolint:gochecknoglobals // the two tables of RFC 3164
var (
	severityNames = [severities]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
	facilityNames = [...]string{
		"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
		"ntp", "audit", "alert", "clock",
		"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
	}
)

// Parse reads one datagram of UniFi's remote syslog into a record. sender
// is the address it came from, kept on the record since nothing else
// authenticates the line; received stands for the time of a line that
// carries none it can read, and gives the year, which RFC 3164 leaves out;
// location is the senders' time zone, which it leaves out too.
//
// Nothing is refused: a line of a shape nobody mapped becomes a record
// with its text whole, and whatever of the header could be read.
func Parse(datagram []byte, sender string, received time.Time, location *time.Location) plugin.Record {
	text := printable(strings.TrimRight(string(datagram), " \t\r\n"))

	line := record{
		Record:   plugin.Record{Time: received, Body: text, Stream: []string{peer}},
		received: received,
	}
	line.add(peer, sender)

	if match := priority.FindStringSubmatch(text); match != nil {
		if pri, err := strconv.Atoi(match[1]); err == nil && pri <= maxPri {
			line.Severity = severityNames[pri%severities]
			line.add("syslog.facility", facilityNames[pri/severities])

			text = text[len(match[0]):]
		}
	}

	at, rest, timed := timestamp(text, received, location)
	if !timed {
		return line.Record
	}

	line.Time = at

	host, rest, found := strings.Cut(rest, " ")
	if !found || host == "" {
		return line.Record
	}

	line.add("host.name", host)

	if isCEF(rest) {
		line.cef(rest)

		return line.Record
	}

	line.device(host, rest)

	return line.Record
}

// Named is line with who its two ends are: for a firewall line whose
// addresses names knows at the time given, source.name and
// destination.name beside the addresses, as a flow has them. What a line
// gives for an address is its sender's to write; what is not an address is
// asked of nobody, and a name is the collector's own word, never the
// line's.
func Named(line plugin.Record, names *plugin.Names, when time.Time) plugin.Record {
	for _, end := range [...]struct{ address, name string }{
		{sourceAddress, sourceName},
		{destinationAddress, destinationName},
	} {
		for _, field := range line.Fields {
			if field.Name != end.address {
				continue
			}

			if where, err := netip.ParseAddr(field.Value); err == nil {
				if called := names.Of(where, when); called != "" {
					line.Fields = append(line.Fields, plugin.Field{Name: end.name, Value: called})
				}
			}

			break
		}
	}

	return line
}

// record is a plugin.Record being filled, and when its line was read.
type record struct {
	plugin.Record

	received time.Time
}

// printable is text with what is not UTF-8, and every control character
// but the tab and the line feed, replaced: an escape sequence or a NUL a
// sender put in a line is not handed to whoever prints the store's lines.
func printable(text string) string {
	return strings.Map(func(char rune) rune {
		if unicode.IsControl(char) && char != '\t' && char != '\n' {
			return utf8.RuneError
		}

		return char
	}, strings.ToValidUTF8(text, string(utf8.RuneError)))
}

// near reports whether at is within a day of the reading.
func near(at, received time.Time) bool {
	apart := at.Sub(received)

	return apart <= day && apart >= -day
}

func (r *record) add(name, value string) {
	if value != "" {
		r.Fields = append(r.Fields, plugin.Field{Name: name, Value: value})
	}
}

// timestamp reads the "Mmm dd hh:mm:ss " that heads an RFC 3164 line and
// returns when the line says it happened and what follows. The line gives
// no year: it is the reading's, or the one before for a line of late
// December read in early January, whichever puts the line within a day of
// its reading. A line that neither does, or that names a day its year does
// not have, is dated by its reading.
func timestamp(text string, received time.Time, location *time.Location) (time.Time, string, bool) {
	if len(text) <= len(stamp) || text[len(stamp)] != ' ' {
		return time.Time{}, "", false
	}

	read, err := time.ParseInLocation(stamp, text[:len(stamp)], location)
	if err != nil {
		return time.Time{}, "", false
	}

	rest := text[len(stamp)+1:]
	year := received.In(location).Year()

	for _, candidate := range [...]int{year, year - 1, year + 1} {
		at := time.Date(candidate, read.Month(), read.Day(), read.Hour(), read.Minute(), read.Second(), 0, location)

		// A day the year does not have rolls over into the next month.
		if at.Month() == read.Month() && at.Day() == read.Day() && near(at, received) {
			return at, rest, true
		}
	}

	return received, rest, true
}

// device reads what follows the host name on a device's own line: the
// tag, the program and its pid, and the text.
func (r *record) device(host, rest string) {
	// An access point's tag is "<mac>,<model>-<firmware>: ".
	if tag, after, found := strings.Cut(rest, ": "); found {
		if match := deviceTag.FindStringSubmatch(tag); match != nil {
			r.add("device.id", match[1])
			r.add("device.model.identifier", match[2])
			r.add("os.version", match[3])

			rest = after
		}
	}

	// The gateway puts its own name where the program's belongs
	// ("<name> <program>[pid]: text").
	rest = strings.TrimPrefix(rest, host+" ")
	// An access point sometimes leaves the first program's name empty
	// (": <program>[pid]: text").
	rest = strings.TrimPrefix(rest, ": ")

	r.Body = rest

	if match := firewall.FindStringSubmatch(rest); match != nil {
		r.firewall(rest, match)

		return
	}

	match := program.FindStringSubmatch(rest)
	if match == nil {
		return
	}

	name, pid, text := match[1], match[2], match[3]

	// An access point names the program twice
	// ("<program>: <program>[pid]: text").
	if again := program.FindStringSubmatch(text); len(again) == len(match) && again[1] == name && again[2] != "" {
		pid, text = again[2], again[3]
	}

	r.Body = text
	r.add("service.name", name)
	r.add("process.pid", pid)
}

// firewall reads the gateway's firewall line: the rule and its policy, the
// interfaces, and the packet's addresses, protocol and ports, the ports
// absent when the protocol has none. The text stays whole.
func (r *record) firewall(text string, match []string) {
	r.add("service.name", "firewall")
	r.add("unifi.firewall.rule", match[1])
	r.add("unifi.firewall.policy", match[2])
	r.add("network.interface.in", match[3])
	r.add("network.interface.out", match[4])

	if found := addresses.FindStringSubmatch(text); found != nil {
		r.add(sourceAddress, found[1])
		r.add(destinationAddress, found[2])
	}

	if found := transport.FindStringSubmatch(text); found != nil {
		r.add("network.transport", strings.ToLower(found[1]))
	}

	if found := ports.FindStringSubmatch(text + " "); found != nil {
		r.add("source.port", found[1])
		r.add("destination.port", found[2])
	}
}
