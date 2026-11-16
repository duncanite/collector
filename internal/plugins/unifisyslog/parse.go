package unifisyslog

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/duncanite/collector/internal/plugin"
)

// stamp is the timestamp of an RFC 3164 line: no year, no zone.
const stamp = time.Stamp

// day is how far ahead of its reading a line may be dated before it is
// taken for last year's.
const day = 24 * time.Hour

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
	// "<program>[pid]: text" or "<program>: text".
	program = regexp.MustCompile(`^([A-Za-z0-9_./-]+)(?:\[(\d+)\])?: (.*)$`)
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
	text := strings.TrimRight(strings.ToValidUTF8(string(datagram), "�"), " \t\r\n")

	line := record{Record: plugin.Record{Time: received, Body: text}}
	line.add("network.peer.address", sender)

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

// record is a plugin.Record being filled.
type record struct {
	plugin.Record
}

func (r *record) add(name, value string) {
	if value != "" {
		r.Fields = append(r.Fields, plugin.Field{Name: name, Value: value})
	}
}

// timestamp reads the "Mmm dd hh:mm:ss " that heads an RFC 3164 line and
// returns what follows it. The year is received's, or the one before when
// that would put the line more than a day ahead: a line of late December
// read in early January.
func timestamp(text string, received time.Time, location *time.Location) (time.Time, string, bool) {
	if len(text) <= len(stamp) || text[len(stamp)] != ' ' {
		return time.Time{}, "", false
	}

	read, err := time.ParseInLocation(stamp, text[:len(stamp)], location)
	if err != nil {
		return time.Time{}, "", false
	}

	year := received.In(location).Year()

	at := time.Date(year, read.Month(), read.Day(), read.Hour(), read.Minute(), read.Second(), 0, location)
	if at.After(received.Add(day)) {
		at = at.AddDate(-1, 0, 0)
	}

	return at, text[len(stamp)+1:], true
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
		r.add("source.address", found[1])
		r.add("destination.address", found[2])
	}

	if found := transport.FindStringSubmatch(text); found != nil {
		r.add("network.transport", strings.ToLower(found[1]))
	}

	if found := ports.FindStringSubmatch(text + " "); found != nil {
		r.add("source.port", found[1])
		r.add("destination.port", found[2])
	}
}
