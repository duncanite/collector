package ipfix

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/duncanite/collector/internal/plugin"
)

// The protocol's own numbers (RFC 7011).
const (
	version      = 10
	headerSize   = 16 // a message's header
	setHeader    = 4  // a set's: its number and its length
	recordHeader = 4  // a template's: its number and how many fields
	scopeCount   = 2  // what an options template adds to it
	specifier    = 4  // one field of a template: element and length
	enterprise   = 4  // what a field of an enterprise's adds to it
	templateSet  = 2
	optionsSet   = 3
	// firstData is the least number of a data set, and so of a template.
	firstData = 256
	// variable is the length of a field whose every value says its own.
	variable = 65535
	// long is the first octet of a variable length that takes two more.
	long = 255
	// private is the bit of an element number that says an enterprise's
	// number follows.
	private = 0x8000
)

// What one exporter, or anyone who writes to the port, can make the reader
// hold and write.
const (
	// mostTemplates is how many templates are held, over every exporter:
	// one more puts out the one defined longest ago.
	mostTemplates = 256
	// mostFields is how many fields a template may have.
	mostFields = 128
	// mostRecords is how many records are read from one datagram: several
	// times what fits in one of an Ethernet's size.
	mostRecords = 512
)

// day is how far from its reading a record's own time is believed.
const day = 24 * time.Hour

// peer is the field the exporter's address is written under, and the one
// the store groups the plugin's records by.
const peer = "network.peer.address"

var (
	// ErrNotIPFIX is a datagram that is no IPFIX message at all: too
	// short for a header, or of another version, NetFlow 9 among them.
	ErrNotIPFIX = errors.New("not an IPFIX message")
	// ErrMalformed is a message that does not hold what its lengths say.
	ErrMalformed = errors.New("a malformed IPFIX message")
	// ErrNoTemplate is a data set read before its template: an exporter
	// sends its templates again every so many datagrams, and what comes
	// before the first of them is not read.
	ErrNoTemplate = errors.New("a data set whose template was not received")
	// ErrTooMany is a datagram of more records than one is read for.
	ErrTooMany = errors.New("more records than one datagram is read for")
)

// scope is what a template's number is unique in: one exporter, its
// address and port, and one of its observation domains.
type scope struct {
	exporter netip.AddrPort
	domain   uint32
	id       uint16
}

// field is one field of a template.
type field struct {
	id         uint16
	length     uint16
	enterprise uint32
}

// template is how the records of one data set are laid out.
type template struct {
	fields []field
	// least is the fewest octets a record of it takes.
	least int
	// options says the records describe the exporter, not flows.
	options bool
	// turn is when it was last defined, in the reader's count.
	turn uint64
}

// Reader reads IPFIX messages. It holds the templates the exporters
// sent, which is all that a message's reading depends on besides the
// message. It is for one goroutine.
type Reader struct {
	templates map[scope]*template
	turn      uint64
	// names is who an address is, when a plugin of the collector said.
	names *plugin.Names
}

// NewReader returns a reader that holds no template yet.
func NewReader() *Reader {
	return &Reader{templates: make(map[scope]*template)}
}

// Name has the reader write who a flow's two addresses are, as names
// knows them when the flow is read, beside the addresses.
func (r *Reader) Name(names *plugin.Names) { r.names = names }

// Templates is how many templates the reader holds.
func (r *Reader) Templates() int { return len(r.templates) }

// Read reads one datagram from exporter, received at received, into a
// record per flow. The error says what of it was not read; the records
// are the ones that were, and are to be written all the same.
//
// The records of an options template, what the exporter says of itself,
// are skipped.
func (r *Reader) Read(datagram []byte, exporter netip.AddrPort, received time.Time) ([]plugin.Record, error) {
	if len(datagram) < headerSize {
		return nil, fmt.Errorf("%w: %d octets", ErrNotIPFIX, len(datagram))
	}

	if got := binary.BigEndian.Uint16(datagram); got != version {
		return nil, fmt.Errorf("%w: version %d", ErrNotIPFIX, got)
	}

	length := int(binary.BigEndian.Uint16(datagram[2:]))
	if length < headerSize || length > len(datagram) {
		return nil, fmt.Errorf("%w: a length of %d in a datagram of %d", ErrMalformed, length, len(datagram))
	}

	msg := message{
		reader:   r,
		exporter: exporter,
		exported: time.Unix(int64(binary.BigEndian.Uint32(datagram[4:])), 0),
		domain:   binary.BigEndian.Uint32(datagram[12:]),
		received: received,
	}

	var (
		first error
		rest  = datagram[headerSize:length]
	)

	// The first fault is the one told; the sets after it are read all the
	// same, as long as where they start is known.
	for len(rest) >= setHeader {
		size := int(binary.BigEndian.Uint16(rest[2:]))
		if size < setHeader || size > len(rest) {
			break
		}

		if err := msg.set(binary.BigEndian.Uint16(rest), rest[setHeader:size]); first == nil {
			first = err
		}

		rest = rest[size:]
	}

	if len(rest) != 0 && first == nil {
		first = fmt.Errorf("%w: %d octets that are no set", ErrMalformed, len(rest))
	}

	return msg.records, first
}

// keep holds a template, in place of the one of its number when there is
// one, and of the one defined longest ago when there is no room.
func (r *Reader) keep(where scope, kept *template) {
	if _, held := r.templates[where]; !held && len(r.templates) >= mostTemplates {
		var oldest scope

		least := r.turn + 1

		for one, other := range r.templates {
			if other.turn < least {
				oldest, least = one, other.turn
			}
		}

		delete(r.templates, oldest)
	}

	r.turn++
	kept.turn = r.turn
	r.templates[where] = kept
}

// withdraw lets go of the template named, or of every template of its
// exporter and domain when what is named is a template set and not a
// template.
func (r *Reader) withdraw(named scope) {
	switch {
	case named.id >= firstData:
		delete(r.templates, named)
	case named.id == templateSet || named.id == optionsSet:
		// The set's own number withdraws all of its kind, and leaves the
		// other kind: RFC 7011, 8.1.
		options := named.id == optionsSet

		maps.DeleteFunc(r.templates, func(one scope, held *template) bool {
			return one.exporter == named.exporter && one.domain == named.domain && held.options == options
		})
	}
}

// message is one datagram being read.
type message struct {
	reader   *Reader
	exporter netip.AddrPort
	exported time.Time
	domain   uint32
	received time.Time
	records  []plugin.Record
}

// set reads one set: templates, or the records of one.
func (m *message) set(number uint16, body []byte) error {
	switch {
	case number == templateSet:
		return m.define(body, false)
	case number == optionsSet:
		return m.define(body, true)
	case number < firstData:
		return fmt.Errorf("%w: a set numbered %d", ErrMalformed, number)
	default:
		return m.data(number, body)
	}
}

// define reads a set of templates and holds each. What follows a template
// that does not hold together is not read: where the next one starts is
// not known.
func (m *message) define(body []byte, options bool) error {
	for len(body) >= recordHeader {
		named := scope{exporter: m.exporter, domain: m.domain, id: binary.BigEndian.Uint16(body)}
		count := int(binary.BigEndian.Uint16(body[2:]))
		body = body[recordHeader:]

		// No field: the template is withdrawn. Padding reads as this too,
		// of a template numbered zero, which is none.
		if count == 0 {
			m.reader.withdraw(named)

			continue
		}

		if named.id < firstData || count > mostFields {
			return fmt.Errorf("%w: template %d of %d fields", ErrMalformed, named.id, count)
		}

		defined, rest, ok := laid(body, count, options)
		if !ok {
			return fmt.Errorf("%w: template %d is cut short", ErrMalformed, named.id)
		}

		// A record of no octets would be read without end.
		if defined.least == 0 {
			return fmt.Errorf("%w: template %d has records of no octets", ErrMalformed, named.id)
		}

		body = rest

		m.reader.keep(named, defined)
	}

	return nil
}

// laid reads the count fields of one template at the head of body, and
// returns the template and what follows it.
func laid(body []byte, count int, options bool) (*template, []byte, bool) {
	// How many of an options template's fields are its scope: they are
	// fields like the others to whoever skips its records.
	if options {
		if len(body) < scopeCount {
			return nil, nil, false
		}

		body = body[scopeCount:]
	}

	defined := &template{fields: make([]field, 0, count), options: options}

	for range count {
		one, rest, ok := specified(body)
		if !ok {
			return nil, nil, false
		}

		body = rest

		defined.fields = append(defined.fields, one)

		if one.length == variable {
			defined.least++
		} else {
			defined.least += int(one.length)
		}
	}

	return defined, body, true
}

// specified reads one field of a template, and returns what follows it.
func specified(body []byte) (field, []byte, bool) {
	if len(body) < specifier {
		return field{}, nil, false
	}

	id := binary.BigEndian.Uint16(body)
	one := field{id: id &^ private, length: binary.BigEndian.Uint16(body[2:])}
	body = body[specifier:]

	if id&private != 0 {
		if len(body) < enterprise {
			return field{}, nil, false
		}

		one.enterprise = binary.BigEndian.Uint32(body)
		body = body[enterprise:]
	}

	return one, body, true
}

// data reads the records of one data set by its template. What is left
// after the last record, fewer octets than a record takes, is padding.
func (m *message) data(number uint16, body []byte) error {
	layout, held := m.reader.templates[scope{exporter: m.exporter, domain: m.domain, id: number}]
	if !held {
		return fmt.Errorf("%w: template %d", ErrNoTemplate, number)
	}

	if layout.options {
		return nil
	}

	for len(body) >= layout.least {
		if len(m.records) >= mostRecords {
			return ErrTooMany
		}

		read := flow{fields: make([]plugin.Field, 0, len(layout.fields)+about+named)}

		for _, one := range layout.fields {
			value, rest, ok := take(body, one.length)
			if !ok {
				return fmt.Errorf("%w: a record of template %d is cut short", ErrMalformed, number)
			}

			body = rest

			read.add(one, value)
		}

		m.records = append(m.records, read.record(m, number))
	}

	return nil
}

// take returns the value of a field of the given length at the head of
// body, and what follows it. A variable length is said by the value's
// first octet, or by the two after it when that one is 255.
func take(body []byte, length uint16) (value, rest []byte, ok bool) {
	size := int(length)

	if length == variable {
		if len(body) < 1 {
			return nil, nil, false
		}

		size, body = int(body[0]), body[1:]

		if size == long {
			if len(body) < 2 {
				return nil, nil, false
			}

			size, body = int(binary.BigEndian.Uint16(body)), body[2:]
		}
	}

	if len(body) < size {
		return nil, nil, false
	}

	return body[:size], body[size:], true
}

// about is how many fields a record has that say where it came from, not
// what it holds: the exporter, its domain and the template.
const about = 3

// And two more when its ends are known by name.
const named = 2

// Who the two ends of a flow are, when a plugin of the collector said: the
// collector's own names, OpenTelemetry having none for it.
const (
	sourceName      = "source.name"
	destinationName = "destination.name"
)

// flow is one record being read: its fields, and what of them its text
// and its time are made of.
type flow struct {
	fields []plugin.Field

	transport       string
	source          string
	sourcePort      string
	destination     string
	destinationPort string
	octets          string
	packets         string

	// The two addresses again, as addresses: what a name is asked by.
	sourceAt      netip.Addr
	destinationAt netip.Addr

	// ended is when the flow says it ended, observed when the exporter
	// says it saw what a record with no flow reports.
	ended    time.Time
	observed time.Time
}

// add reads one value of the record.
func (f *flow) add(one field, value []byte) {
	known, ok := elements[one.id]

	// An enterprise's element, or one that is not in the table: its
	// number, and its octets as they are.
	if one.enterprise != 0 || !ok {
		name := own + strconv.FormatUint(uint64(one.id), 10)
		if one.enterprise != 0 {
			name = own + strconv.FormatUint(uint64(one.enterprise), 10) + "." + strconv.FormatUint(uint64(one.id), 10)
		}

		said, _ := opaque.read(value)

		f.field(name, said)

		return
	}

	said, when := known.kind.read(value)

	f.field(known.name, said)

	switch one.id {
	case protocolIdentifier:
		f.transport = said
	case sourceIPv4Address, sourceIPv6Address:
		f.source = said
		f.sourceAt, _ = netip.AddrFromSlice(value)
	case destinationIPv4Address, destinationIPv6Address:
		f.destination = said
		f.destinationAt, _ = netip.AddrFromSlice(value)
	case sourceTransportPort:
		f.sourcePort = said
	case destinationTransportPort:
		f.destinationPort = said
	case octetDeltaCount:
		f.octets = said
	case packetDeltaCount:
		f.packets = said
	case flowEndSeconds, flowEndMilliseconds, flowEndMicroseconds, flowEndNanoseconds:
		f.ended = when
	case observationTimeMilliseconds, observationTimeMicroseconds, observationTimeNanoseconds:
		f.observed = when
	}
}

func (f *flow) field(name, value string) {
	if value != "" {
		f.fields = append(f.fields, plugin.Field{Name: name, Value: value})
	}
}

// record is the flow as a record of the message it came in, read by the
// template of the given number. It is dated by its own end, else by when
// the exporter saw it, else by when the exporter sent it, the first of them
// that is within a day of the datagram's reading; and by that reading when
// none is.
func (f *flow) record(from *message, number uint16) plugin.Record {
	dated := from.received

	for _, said := range [...]time.Time{f.ended, f.observed, from.exported} {
		if apart := said.Sub(from.received); !said.IsZero() && apart <= day && apart >= -day {
			dated = said

			break
		}
	}

	// A name is text someone else chose, a host's own name for one: cut
	// and cleaned as a string of the exporter's is.
	for _, side := range [...]struct {
		name string
		at   netip.Addr
	}{{sourceName, f.sourceAt}, {destinationName, f.destinationAt}} {
		called, _ := text.read([]byte(from.reader.names.Of(side.at, from.received)))

		f.field(side.name, called)
	}

	f.field(peer, from.exporter.Addr().Unmap().String())
	f.field(own+"observationDomainId", strconv.FormatUint(uint64(from.domain), 10))
	f.field(own+"templateId", strconv.FormatUint(uint64(number), 10))

	return plugin.Record{Time: dated, Body: f.text(), Fields: f.fields, Stream: []string{peer}}
}

// text is the record in one line, for whoever reads the store without
// asking for fields: "tcp 192.0.2.7:51000 > 198.51.100.9:443 5344385
// bytes 5009 packets", less what the record does not hold.
func (f *flow) text() string {
	parts := make([]string, 0, about+about)

	if f.transport != "" {
		parts = append(parts, f.transport)
	}

	if f.source != "" || f.destination != "" {
		parts = append(parts, end(f.source, f.sourcePort), ">", end(f.destination, f.destinationPort))
	}

	if f.octets != "" {
		parts = append(parts, f.octets+" bytes")
	}

	if f.packets != "" {
		parts = append(parts, f.packets+" packets")
	}

	if len(parts) == 0 {
		return "flow"
	}

	return strings.Join(parts, " ")
}

// end is one end of a flow: its address, and its port when it has one.
func end(address, port string) string {
	switch {
	case address == "":
		return "?"
	case port == "" || port == "0":
		return address
	default:
		return net.JoinHostPort(address, port)
	}
}
