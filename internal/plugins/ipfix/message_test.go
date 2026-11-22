package ipfix_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/duncanite/collector/internal/plugin"
	"github.com/duncanite/collector/internal/plugins/ipfix"
)

// gateway is where the tests' datagrams are said to come from.
func gateway() netip.AddrPort { return netip.MustParseAddrPort("192.0.2.1:40000") }

// received is when they are said to be read.
func received() time.Time { return time.Date(2026, time.November, 18, 12, 0, 0, 0, time.UTC) }

// pack is values as IPFIX writes them, the most significant octet first.
// A bare number is sixteen bits, the size of nearly everything in a
// header and a template.
func pack(tb testing.TB, values ...any) []byte {
	tb.Helper()

	var out []byte

	for _, value := range values {
		switch value := value.(type) {
		case int:
			out = binary.BigEndian.AppendUint16(out, uint16(value))
		case uint8:
			out = append(out, value)
		case uint32:
			out = binary.BigEndian.AppendUint32(out, value)
		case uint64:
			out = binary.BigEndian.AppendUint64(out, value)
		case netip.Addr:
			out = append(out, value.AsSlice()...)
		case string:
			out = append(out, value...)
		case []byte:
			out = append(out, value...)
		default:
			tb.Fatalf("pack: a %T", value)
		}
	}

	return out
}

// set is one set: its number, its length, and what it holds.
func set(tb testing.TB, id int, values ...any) []byte {
	tb.Helper()

	body := pack(tb, values...)

	return append(pack(tb, id, len(body)+4), body...)
}

// message is one IPFIX message of the given export time and observation
// domain.
func message(tb testing.TB, exported time.Time, domain uint32, sets ...[]byte) []byte {
	tb.Helper()

	body := bytes.Join(sets, nil)

	return append(pack(tb, 10, len(body)+16, uint32(exported.Unix()), uint32(0), domain), body...)
}

// template is a template set of one template: its number, then an element
// and a length per field.
func template(tb testing.TB, id int, pairs ...int) []byte {
	tb.Helper()

	values := []any{id, len(pairs) / 2}
	for _, one := range pairs {
		values = append(values, one)
	}

	return set(tb, 2, values...)
}

func addr(text string) netip.Addr { return netip.MustParseAddr(text) }

// fields is a record's fields by name.
func fields(record plugin.Record) map[string]string {
	out := make(map[string]string, len(record.Fields))
	for _, field := range record.Fields {
		out[field.Name] = field.Value
	}

	return out
}

// read reads datagram from the gateway and fails the test on any error.
func read(t *testing.T, reader *ipfix.Reader, datagram []byte) []plugin.Record {
	t.Helper()

	records, err := reader.Read(datagram, gateway(), received())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	return records
}

// TestTheRFCsOwnExampleIsRead reads the message of RFC 7011's appendix A:
// a template, three flows by it, an options template, and two records by
// that one, which say nothing of a flow and are not written.
func TestTheRFCsOwnExampleIsRead(t *testing.T) {
	t.Parallel()

	datagram := message(t, received(), 1,
		set(t, 2, 256, 5, 8, 4, 12, 4, 15, 4, 2, 4, 1, 4),
		set(t, 256,
			addr("192.0.2.12"), addr("192.0.2.254"), addr("192.0.2.1"), uint32(5009), uint32(5344385),
			addr("192.0.2.27"), addr("192.0.2.23"), addr("192.0.2.2"), uint32(748), uint32(388934),
			addr("192.0.2.56"), addr("192.0.2.65"), addr("192.0.2.3"), uint32(5), uint32(6534),
		),
		// lineCardId as the scope, two counters, and the RFC's two octets
		// of padding.
		set(t, 3, 258, 3, 1, 141, 4, 41, 2, 42, 2, 0),
		set(t, 258, uint32(1), 345, 10201, uint32(2), 690, 20402),
	)

	// The RFC's header gives the message's length.
	if len(datagram) != 152 {
		t.Fatalf("the example is %d octets, the RFC's is 152", len(datagram))
	}

	reader := ipfix.NewReader()
	records := read(t, reader, datagram)

	var bodies []string
	for _, record := range records {
		bodies = append(bodies, record.Body)
	}

	if want := []string{
		"192.0.2.12 > 192.0.2.254 5344385 bytes 5009 packets",
		"192.0.2.27 > 192.0.2.23 388934 bytes 748 packets",
		"192.0.2.56 > 192.0.2.65 6534 bytes 5 packets",
	}; !slices.Equal(bodies, want) {
		t.Fatalf("the flows are %q, want %q", bodies, want)
	}

	if want := map[string]string{
		"source.address":             "192.0.2.12",
		"destination.address":        "192.0.2.254",
		"ipfix.ipNextHopIPv4Address": "192.0.2.1",
		"ipfix.packetDeltaCount":     "5009",
		"ipfix.octetDeltaCount":      "5344385",
		"network.peer.address":       "192.0.2.1",
		"ipfix.observationDomainId":  "1",
		"ipfix.templateId":           "256",
	}; !maps.Equal(fields(records[0]), want) {
		t.Errorf("the first flow's fields are %v, want %v", fields(records[0]), want)
	}

	// A flow that says nothing of its time is dated by its export.
	if !records[0].Time.Equal(received()) || !slices.Equal(records[0].Stream, []string{"network.peer.address"}) {
		t.Errorf("dated %s in the streams of %q", records[0].Time, records[0].Stream)
	}

	if reader.Templates() != 2 {
		t.Errorf("%d templates are held, want the two", reader.Templates())
	}
}

// TestAGatewaysFlowIsReadFieldByField reads one flow of every kind of
// value: what a gateway that translates addresses says of a connection.
func TestAGatewaysFlowIsReadFieldByField(t *testing.T) {
	t.Parallel()

	began := received().Add(-63 * time.Second)
	ended := received().Add(-3 * time.Second)

	datagram := message(t, received(), 7,
		set(t, 2, 300, 18,
			8, 4, 12, 4, 7, 2, 11, 2, 4, 1, 1, 8, 2, 8, 152, 8, 153, 8, 10, 4, 14, 4,
			6, 1, // tcpControlBits in one octet of its two
			225, 4, 227, 2, 56, 6,
			82, 65535, // interfaceName, each value saying its length
			0x8000|77, 4, uint32(4413), // an enterprise's own element
			999, 2, // one of IANA's this package has no name for
		),
		set(t, 300,
			addr("192.0.2.7"), addr("198.51.100.9"), 51000, 443, uint8(6),
			uint64(5344385), uint64(5009), uint64(began.UnixMilli()), uint64(ended.UnixMilli()),
			uint32(4), uint32(2), uint8(27),
			addr("203.0.113.5"), 61000, []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x07},
			uint8(4), "br20",
			uint32(42),
			[]byte{0xbe, 0xef},
		),
	)

	records := read(t, ipfix.NewReader(), datagram)
	if len(records) != 1 {
		t.Fatalf("%d records, want the one", len(records))
	}

	if want := "tcp 192.0.2.7:51000 > 198.51.100.9:443 5344385 bytes 5009 packets"; records[0].Body != want {
		t.Errorf("the flow reads %q, want %q", records[0].Body, want)
	}

	if !records[0].Time.Equal(ended) {
		t.Errorf("dated %s, want its end, %s", records[0].Time, ended)
	}

	if want := map[string]string{
		"source.address":                    "192.0.2.7",
		"destination.address":               "198.51.100.9",
		"source.port":                       "51000",
		"destination.port":                  "443",
		"network.transport":                 "tcp",
		"ipfix.octetDeltaCount":             "5344385",
		"ipfix.packetDeltaCount":            "5009",
		"ipfix.flowStartMilliseconds":       "2026-11-18T11:58:57Z",
		"ipfix.flowEndMilliseconds":         "2026-11-18T11:59:57Z",
		"ipfix.ingressInterface":            "4",
		"ipfix.egressInterface":             "2",
		"ipfix.tcpControlBits":              "27",
		"ipfix.postNATSourceIPv4Address":    "203.0.113.5",
		"ipfix.postNAPTSourceTransportPort": "61000",
		"ipfix.sourceMacAddress":            "00:00:5e:00:53:07",
		"ipfix.interfaceName":               "br20",
		"ipfix.4413.77":                     "0000002a",
		"ipfix.999":                         "beef",
		"network.peer.address":              "192.0.2.1",
		"ipfix.observationDomainId":         "7",
		"ipfix.templateId":                  "300",
	}; !maps.Equal(fields(records[0]), want) {
		t.Errorf("the fields are\n%v, want\n%v", fields(records[0]), want)
	}
}

// TestTheOptionsAndTheFrameTypeHaveTheirNames reads the two elements a
// UniFi gateway sends beside the usual ones: the TCP options seen, in four
// octets of the element's eight, and the type of the Ethernet frame. Both
// are numbers under IANA's names, and not hex under 209 and 256.
func TestTheOptionsAndTheFrameTypeHaveTheirNames(t *testing.T) {
	t.Parallel()

	datagram := message(t, received(), 0,
		template(t, 258, 8, 4, 12, 4, 209, 4, 256, 2),
		set(t, 258, addr("192.0.2.7"), addr("198.51.100.9"), uint32(0x0d000000), 0x86dd),
	)

	records := read(t, ipfix.NewReader(), datagram)
	if len(records) != 1 {
		t.Fatalf("%d records, want the one", len(records))
	}

	got := fields(records[0])

	for name, want := range map[string]string{
		"ipfix.tcpOptions":   "218103808",
		"ipfix.ethernetType": "34525",
	} {
		if got[name] != want {
			t.Errorf("%s is %q, want %q", name, got[name], want)
		}
	}

	for _, number := range []string{"ipfix.209", "ipfix.256"} {
		if value, written := got[number]; written {
			t.Errorf("%s is written, %q: the element has a name", number, value)
		}
	}
}

// TestAFlowsEndsAreNamedWhenSomeoneSaidWhoTheyAre reads a flow each way
// between a host the collector was told the name of and one it was not:
// the name is beside the address of the end it is the name of, and the
// other end has none.
func TestAFlowsEndsAreNamedWhenSomeoneSaidWhoTheyAre(t *testing.T) {
	t.Parallel()

	names := plugin.NewNames()
	names.Tell("console", map[netip.Addr]string{addr("192.0.2.7"): "Laptop"}, received())

	reader := ipfix.NewReader()
	reader.Name(names)

	records := read(t, reader, message(t, received(), 0,
		template(t, 256, 8, 4, 12, 4),
		set(t, 256,
			addr("192.0.2.7"), addr("198.51.100.9"),
			addr("198.51.100.9"), addr("192.0.2.7"),
		),
	))
	if len(records) != 2 {
		t.Fatalf("%d records, want the two", len(records))
	}

	for index, want := range []map[string]string{
		{"source.name": "Laptop", "destination.name": ""},
		{"source.name": "", "destination.name": "Laptop"},
	} {
		got := fields(records[index])

		for name, value := range want {
			if got[name] != value {
				t.Errorf("flow %d: %s is %q, want %q", index, name, got[name], value)
			}
		}
	}

	// The name is no part of the flow's line: the line is what the
	// exporter said.
	if want := "192.0.2.7 > 198.51.100.9"; records[0].Body != want {
		t.Errorf("the flow reads %q, want %q", records[0].Body, want)
	}
}

// TestANameItsTellerNoLongerStandsByIsNotWritten reads the same flow a
// moment after the names' time: an address may be another host's by then.
func TestANameItsTellerNoLongerStandsByIsNotWritten(t *testing.T) {
	t.Parallel()

	names := plugin.NewNames()
	names.Tell("console", map[netip.Addr]string{addr("192.0.2.7"): "Laptop"}, received().Add(-time.Second))

	reader := ipfix.NewReader()
	reader.Name(names)

	records := read(t, reader, message(t, received(), 0,
		template(t, 256, 8, 4, 12, 4),
		set(t, 256, addr("192.0.2.7"), addr("198.51.100.9")),
	))
	if len(records) != 1 {
		t.Fatalf("%d records, want the one", len(records))
	}

	if got, written := fields(records[0])["source.name"]; written {
		t.Errorf("the source is named %q by a word that no longer stands", got)
	}
}

// TestANameIsCutAndCleanedAsAnyText reads a flow of a host that calls
// itself by an escape sequence and four hundred letters: a host chooses its
// own name, and what it chose is not handed on as it came.
func TestANameIsCutAndCleanedAsAnyText(t *testing.T) {
	t.Parallel()

	names := plugin.NewNames()
	names.Tell("console", map[netip.Addr]string{addr("192.0.2.7"): "\x1b[31m" + strings.Repeat("a", 400)}, received())

	reader := ipfix.NewReader()
	reader.Name(names)

	records := read(t, reader, message(t, received(), 0,
		template(t, 256, 8, 4, 12, 4),
		set(t, 256, addr("192.0.2.7"), addr("198.51.100.9")),
	))
	if len(records) != 1 {
		t.Fatalf("%d records, want the one", len(records))
	}

	// 256 octets of the name are read: the escape, then "[31m" and 251 letters.
	if want := "\uFFFD[31m" + strings.Repeat("a", 251); fields(records[0])["source.name"] != want {
		t.Errorf("the source is named %q, want %q", fields(records[0])["source.name"], want)
	}
}

func TestAFlowOverIPv6(t *testing.T) {
	t.Parallel()

	// Its end as NTP writes a time: seconds since 1900, and a fraction.
	ended := received().Add(-2 * time.Second)

	datagram := message(t, received(), 7,
		template(t, 301, 27, 16, 28, 16, 4, 1, 7, 2, 11, 2, 1, 4, 2, 4, 155, 8),
		set(t, 301,
			addr("2001:db8::7"), addr("2001:db8::9"), uint8(58), 0, 0, uint32(96), uint32(1),
			uint32(ended.Unix()+2208988800), uint32(1<<31),
		),
		// The same over TCP, to see an address of this family with a port.
		set(t, 301,
			addr("2001:db8::7"), addr("2001:db8::9"), uint8(6), 51000, 443, uint32(96), uint32(1),
			uint32(ended.Unix()+2208988800), uint32(0),
		),
		// And a protocol with no name here.
		set(t, 301,
			addr("2001:db8::7"), addr("2001:db8::9"), uint8(47), 0, 0, uint32(96), uint32(1),
			uint32(ended.Unix()+2208988800), uint32(0),
		),
	)

	records := read(t, ipfix.NewReader(), datagram)

	var bodies []string
	for _, record := range records {
		bodies = append(bodies, record.Body)
	}

	if want := []string{
		"icmpv6 2001:db8::7 > 2001:db8::9 96 bytes 1 packets",
		"tcp [2001:db8::7]:51000 > [2001:db8::9]:443 96 bytes 1 packets",
		"47 2001:db8::7 > 2001:db8::9 96 bytes 1 packets",
	}; !slices.Equal(bodies, want) {
		t.Fatalf("the flows are %q, want %q", bodies, want)
	}

	if want := ended.Add(500 * time.Millisecond); !records[0].Time.Equal(want) {
		t.Errorf("dated %s, want %s", records[0].Time, want)
	}
}

// TestARecordIsDatedWithinADayOfItsReading: by its end, else by when the
// exporter saw it, else by its export, the first that is near; by its
// reading when none is.
func TestARecordIsDatedWithinADayOfItsReading(t *testing.T) {
	t.Parallel()

	far := received().Add(-72 * time.Hour)
	seen := received().Add(-5 * time.Second)
	sent := received().Add(-time.Second)

	for name, test := range map[string]struct {
		ended    time.Time
		seen     time.Time
		exported time.Time
		want     time.Time
	}{
		"its end":                                {seen.Add(-time.Second), seen, sent, seen.Add(-time.Second)},
		"an end long ago: when it was seen":      {far, seen, sent, seen},
		"neither near: its export":               {far, far, sent, sent},
		"nothing near: its reading":              {far, far, far, received()},
		"an end in the future: when it was sent": {received().Add(72 * time.Hour), far, sent, sent},
	} {
		datagram := message(t, test.exported, 1,
			template(t, 256, 8, 4, 153, 8, 323, 8),
			set(t, 256, addr("192.0.2.7"), uint64(test.ended.UnixMilli()), uint64(test.seen.UnixMilli())),
		)

		records := read(t, ipfix.NewReader(), datagram)
		if len(records) != 1 {
			t.Fatalf("%s: %d records, want the one", name, len(records))
		}

		if !records[0].Time.Equal(test.want) {
			t.Errorf("%s: dated %s, want %s", name, records[0].Time, test.want)
		}
	}
}

// TestATemplateIsItsExportersOwn: a data set is read by the template its
// own exporter sent for its own domain, by the latest of them, and by none
// once it is withdrawn.
func TestATemplateIsItsExportersOwn(t *testing.T) {
	t.Parallel()

	reader := ipfix.NewReader()
	flows := message(t, received(), 1, set(t, 256, addr("192.0.2.7"), addr("198.51.100.9")))

	// Before its template: not read, and said so.
	if records, err := reader.Read(flows, gateway(), received()); len(records) != 0 ||
		!errors.Is(err, ipfix.ErrNoTemplate) {
		t.Fatalf("a data set before its template: %d records, %v", len(records), err)
	}

	read(t, reader, message(t, received(), 1, template(t, 256, 8, 4, 12, 4)))

	if records := read(t, reader, flows); len(records) != 1 || records[0].Body != "192.0.2.7 > 198.51.100.9" {
		t.Fatalf("after its template: %v", records)
	}

	// Another port of the same address is another exporter, and another
	// domain another scope.
	other := netip.MustParseAddrPort("192.0.2.1:40001")
	if _, err := reader.Read(flows, other, received()); !errors.Is(err, ipfix.ErrNoTemplate) {
		t.Errorf("read by another exporter's template: %v", err)
	}

	elsewhere := message(t, received(), 2, set(t, 256, addr("192.0.2.7"), addr("198.51.100.9")))
	if _, err := reader.Read(elsewhere, gateway(), received()); !errors.Is(err, ipfix.ErrNoTemplate) {
		t.Errorf("read by another domain's template: %v", err)
	}

	// Defined again, the other way around: the latest is the one.
	read(t, reader, message(t, received(), 1, template(t, 256, 12, 4, 8, 4)))

	if records := read(t, reader, flows); len(records) != 1 || records[0].Body != "198.51.100.9 > 192.0.2.7" {
		t.Errorf("after its template was defined again: %v", records)
	}

	// Withdrawn: a template of no field.
	read(t, reader, message(t, received(), 1, set(t, 2, 256, 0)))

	if _, err := reader.Read(
		flows,
		gateway(),
		received(),
	); !errors.Is(err, ipfix.ErrNoTemplate) ||
		reader.Templates() != 0 {
		t.Errorf("after its template was withdrawn: %v, %d held", err, reader.Templates())
	}

	// All of a domain's at once: the template set's own number, and no
	// field.
	read(t, reader, message(t, received(), 1, template(t, 256, 8, 4), template(t, 257, 8, 4)))
	read(t, reader, message(t, received(), 2, template(t, 256, 8, 4)))
	read(t, reader, message(t, received(), 1, set(t, 2, 2, 0)))

	if reader.Templates() != 1 {
		t.Errorf("%d templates after a domain's were withdrawn, want the other domain's one", reader.Templates())
	}

	// And only its own exporter's: another's withdrawal of the same domain
	// leaves it.
	if _, err := reader.Read(message(t, received(), 2, set(t, 2, 2, 0)), other, received()); err != nil ||
		reader.Templates() != 1 {
		t.Errorf("after another exporter withdrew its own: %v, %d held", err, reader.Templates())
	}
}

// TestAllOfAKindAreWithdrawnAndTheOtherKindKept: the template set's own
// number withdraws a domain's templates and leaves its options templates,
// and the options set's own number the other way around.
func TestAllOfAKindAreWithdrawnAndTheOtherKindKept(t *testing.T) {
	t.Parallel()

	reader := ipfix.NewReader()
	flows := message(t, received(), 1, set(t, 256, addr("192.0.2.7")))

	define := func() {
		read(t, reader, message(t, received(), 1,
			template(t, 256, 8, 4),
			// An options template: a scope of one field, and one more.
			set(t, 3, 258, 2, 1, 141, 4, 41, 2),
		))
	}

	define()

	if reader.Templates() != 2 {
		t.Fatalf("%d templates held, want the two", reader.Templates())
	}

	// All templates: the flows are not read any more, the options
	// template is still held.
	read(t, reader, message(t, received(), 1, set(t, 2, 2, 0)))

	if _, err := reader.Read(flows, gateway(), received()); !errors.Is(err, ipfix.ErrNoTemplate) ||
		reader.Templates() != 1 {
		t.Errorf("after all templates were withdrawn: %v, %d held, want the options template", err, reader.Templates())
	}

	// All options templates: the flows' template is the one kept.
	define()
	read(t, reader, message(t, received(), 1, set(t, 3, 3, 0)))

	if records := read(t, reader, flows); len(records) != 1 || reader.Templates() != 1 {
		t.Errorf("after all options templates were withdrawn: %d records, %d held", len(records), reader.Templates())
	}
}

// TestATimeTooFarToHoldIsWrittenAsItCame: milliseconds past what a time
// here can count are no time: the field is written in hex, and the record
// is dated by something else.
func TestATimeTooFarToHoldIsWrittenAsItCame(t *testing.T) {
	t.Parallel()

	records := read(t, ipfix.NewReader(), message(t, received(), 1,
		template(t, 256, 8, 4, 153, 8),
		set(t, 256, addr("192.0.2.7"), uint64(1<<63)),
	))
	if len(records) != 1 {
		t.Fatalf("%d records, want the one", len(records))
	}

	if got := fields(records[0])["ipfix.flowEndMilliseconds"]; got != "8000000000000000" {
		t.Errorf("the end is written %q, want its octets in hex", got)
	}

	if !records[0].Time.Equal(received()) {
		t.Errorf("dated %s, want its export, %s", records[0].Time, received())
	}
}

// TestTheTemplatesHeldAreBounded: one more than there is room for puts
// out the one defined longest ago, and a template defined again is as new.
func TestTheTemplatesHeldAreBounded(t *testing.T) {
	t.Parallel()

	const most = 256

	reader := ipfix.NewReader()

	for id := range most {
		read(t, reader, message(t, received(), 1, template(t, 256+id, 8, 4)))
	}

	// The first, defined again, is the newest; the second is now the
	// oldest.
	read(t, reader, message(t, received(), 1, template(t, 256, 8, 4)))
	read(t, reader, message(t, received(), 1, template(t, 256+most, 8, 4)))

	if reader.Templates() != most {
		t.Fatalf("%d templates are held, want %d", reader.Templates(), most)
	}

	for id, held := range map[int]bool{256: true, 257: false, 258: true, 256 + most: true} {
		_, err := reader.Read(message(t, received(), 1, set(t, id, addr("192.0.2.7"))), gateway(), received())
		if held != (err == nil) || !held && !errors.Is(err, ipfix.ErrNoTemplate) {
			t.Errorf("template %d: held is %t, and reading by it gives %v", id, held, err)
		}
	}
}

// TestWhatAMessageGetsWrong: each is refused by its kind, and what was
// read before the fault is kept.
func TestWhatAMessageGetsWrong(t *testing.T) {
	t.Parallel()

	good := template(t, 256, 8, 4)
	flow := set(t, 256, addr("192.0.2.7"))

	fields := []any{257, 129}
	for range 129 {
		fields = append(fields, 8, 4)
	}

	many := []any{}
	for range 600 {
		many = append(many, addr("192.0.2.7"))
	}

	for name, test := range map[string]struct {
		datagram []byte
		want     error
		records  int
	}{
		"nothing":                    {nil, ipfix.ErrNotIPFIX, 0},
		"shorter than a header":      {message(t, received(), 1)[:15], ipfix.ErrNotIPFIX, 0},
		"NetFlow 9":                  {append([]byte{0, 9}, message(t, received(), 1)[2:]...), ipfix.ErrNotIPFIX, 0},
		"a length past the datagram": {message(t, received(), 1, good, flow)[:30], ipfix.ErrMalformed, 0},
		"a length under a header's":  {pack(t, 10, 15, uint32(0), uint32(0), uint32(1)), ipfix.ErrMalformed, 0},
		"a set past the message": {
			message(t, received(), 1, good, flow, pack(t, 256, 12, addr("192.0.2.7"))), ipfix.ErrMalformed, 1,
		},
		"a set shorter than its header": {message(t, received(), 1, good, flow, pack(t, 256, 3)), ipfix.ErrMalformed, 1},
		"octets after the last set":     {message(t, received(), 1, good, flow, []byte{0, 0}), ipfix.ErrMalformed, 1},
		"a set of a reserved number":    {message(t, received(), 1, good, set(t, 5, 0, 0), flow), ipfix.ErrMalformed, 1},
		"a template numbered as no data set is": {
			message(t, received(), 1, good, template(t, 255, 8, 4), flow), ipfix.ErrMalformed, 1,
		},
		"a template of too many fields": {message(t, received(), 1, good, set(t, 2, fields...), flow), ipfix.ErrMalformed, 1},
		"a template cut short":          {message(t, received(), 1, good, set(t, 2, 257, 2, 8, 4), flow), ipfix.ErrMalformed, 1},
		"an enterprise's field cut short": {
			message(t, received(), 1, good, set(t, 2, 257, 1, 0x8000|8, 4, 0), flow), ipfix.ErrMalformed, 1,
		},
		"an options template cut short": {message(t, received(), 1, good, set(t, 3, 257, 1), flow), ipfix.ErrMalformed, 1},
		"a template whose records take no octet": {
			message(t, received(), 1, good, template(t, 257, 8, 0), flow), ipfix.ErrMalformed, 1,
		},
		"a value longer than what is left": {
			message(t, received(), 1, good, flow, template(t, 257, 82, 65535), set(t, 257, uint8(9), "br20")),
			ipfix.ErrMalformed, 1,
		},
		"a long length cut short": {
			message(t, received(), 1, good, flow, template(t, 257, 82, 65535), set(t, 257, uint8(255), uint8(0))),
			ipfix.ErrMalformed, 1,
		},
		"more flows than a datagram is read for": {
			message(t, received(), 1, good, set(t, 256, many...)), ipfix.ErrTooMany, 512,
		},
	} {
		records, err := ipfix.NewReader().Read(test.datagram, gateway(), received())
		if !errors.Is(err, test.want) || len(records) != test.records {
			t.Errorf("%s: %d records and %v, want %d and %v", name, len(records), err, test.records, test.want)
		}
	}
}

// TestAValueIsBoundedAndPrintable: a name an exporter writes is cut and
// cleaned, octets with no reading are cut, and a value of a size its
// element does not come in is written as the octets it is.
func TestAValueIsBoundedAndPrintable(t *testing.T) {
	t.Parallel()

	datagram := message(t, received(), 1,
		set(t, 2, 256, 6, 82, 65535, 83, 65535, 999, 65535, 8, 5, 56, 4, 153, 4),
		set(t, 256,
			uint8(9), "br\x1b[2J0\x00\xff",
			// A length of three octets: 255, then the length itself.
			uint8(255), 300, strings.Repeat("a", 300),
			uint8(100), bytes.Repeat([]byte{0xab}, 100),
			[]byte{192, 0, 2, 7, 9},
			[]byte{0, 0, 0x5e, 0},
			uint32(1),
		),
	)

	records := read(t, ipfix.NewReader(), datagram)
	if len(records) != 1 {
		t.Fatalf("%d records, want the one", len(records))
	}

	got := fields(records[0])

	for name, want := range map[string]string{
		"ipfix.interfaceName":        "br�[2J0��",
		"ipfix.interfaceDescription": strings.Repeat("a", 256),
		"ipfix.999":                  strings.Repeat("ab", 64),
		"source.address":             "c000020709",
		"ipfix.sourceMacAddress":     "00005e00",
		"ipfix.flowEndMilliseconds":  "00000001",
	} {
		if got[name] != want {
			t.Errorf("%s is %q, want %q", name, got[name], want)
		}
	}

	// An address that is none is not one end of the flow's text either,
	// and a time that is none dates nothing.
	if records[0].Body != "c000020709 > ?" || !records[0].Time.Equal(received()) {
		t.Errorf("the flow reads %q, dated %s", records[0].Body, records[0].Time)
	}
}

// TestAStringOfNothingPrintableIsThreeTimesWhatWasRead: the 256 octets
// read of a string are each a mark of three when none is text, which is
// the most a string stores.
func TestAStringOfNothingPrintableIsThreeTimesWhatWasRead(t *testing.T) {
	t.Parallel()

	records := read(t, ipfix.NewReader(), message(t, received(), 1,
		template(t, 256, 82, 65535),
		set(t, 256, uint8(255), 300, strings.Repeat("\x00", 300)),
	))
	if len(records) != 1 {
		t.Fatalf("%d records, want the one", len(records))
	}

	const read, mark = 256, 3

	if got := fields(records[0])["ipfix.interfaceName"]; got != strings.Repeat("\ufffd", read) ||
		len(got) != read*mark {
		t.Errorf("the name is %d octets, want %d: %q", len(got), read*mark, got)
	}
}

func TestPaddingIsNotAFlow(t *testing.T) {
	t.Parallel()

	datagram := message(t, received(), 1,
		// Padding after a template, as long as a template's header.
		set(t, 2, 256, 2, 8, 4, 12, 4, 0, 0),
		// And after a record, shorter than one.
		set(t, 256, addr("192.0.2.7"), addr("198.51.100.9"), []byte{0, 0, 0}),
	)

	reader := ipfix.NewReader()

	if records := read(t, reader, datagram); len(records) != 1 || reader.Templates() != 1 {
		t.Errorf("%d records and %d templates, want one of each", len(records), reader.Templates())
	}
}

// TestWhatFollowsTheMessageIsNotRead: a message ends where its header
// says, whatever the datagram holds after.
func TestWhatFollowsTheMessageIsNotRead(t *testing.T) {
	t.Parallel()

	datagram := message(t, received(), 1, template(t, 256, 8, 4), set(t, 256, addr("192.0.2.7")))
	datagram = append(datagram, set(t, 256, addr("192.0.2.8"))...)

	if records := read(t, ipfix.NewReader(), datagram); len(records) != 1 || records[0].Body != "192.0.2.7 > ?" {
		t.Errorf("the flows are %v, want the one of the message", records)
	}
}

func FuzzRead(f *testing.F) {
	f.Add(message(f, received(), 1,
		set(f, 2, 256, 5, 8, 4, 12, 4, 15, 4, 2, 4, 1, 4),
		set(f, 256, addr("192.0.2.12"), addr("192.0.2.254"), addr("192.0.2.1"), uint32(5009), uint32(5344385)),
		set(f, 3, 258, 3, 1, 141, 4, 41, 2, 42, 2, 0),
		set(f, 258, uint32(1), 345, 10201),
	))
	f.Add(message(f, received(), 7,
		set(f, 2, 300, 6, 27, 16, 4, 1, 153, 8, 82, 65535, 0x8000|77, 4, uint32(4413), 155, 8),
		set(f, 300, addr("2001:db8::7"), uint8(6), uint64(received().UnixMilli()), uint8(4), "br20",
			uint32(42), uint32(received().Unix()+2208988800), uint32(0)),
	))
	f.Add(
		message(f, received(), 1, template(f, 256, 82, 65535), set(f, 256, uint8(255), 300, strings.Repeat("a", 300))),
	)
	f.Add(message(f, received(), 1, template(f, 256, 8, 0), set(f, 256, addr("192.0.2.7"))))
	f.Add(message(f, received(), 1, set(f, 2, 2, 0), set(f, 2, 256, 0)))
	f.Add([]byte{0, 9, 0, 1})

	f.Fuzz(func(t *testing.T, datagram []byte) {
		reader := ipfix.NewReader()

		// Twice: what the first reading defines, the second reads by.
		for range 2 {
			records, _ := reader.Read(datagram, gateway(), received())

			if len(records) > 512 {
				t.Errorf("%d records of one datagram", len(records))
			}

			for _, record := range records {
				// A template's fields, and the three that say where the
				// record came from.
				if len(record.Fields) > 128+3 {
					t.Errorf("a record of %d fields", len(record.Fields))
				}

				if apart := record.Time.Sub(received()); apart > 24*time.Hour || apart < -24*time.Hour {
					t.Errorf("a record dated %s, read at %s", record.Time, received())
				}

				said := []string{record.Body}
				for _, field := range record.Fields {
					said = append(said, field.Name, field.Value)
				}

				for _, text := range said {
					if !utf8.ValidString(text) || strings.ContainsFunc(text, func(char rune) bool {
						return unicode.IsControl(char) && char != '\t' && char != '\n'
					}) {
						t.Errorf("text a printer would obey, or that is not UTF-8: %q", text)
					}
				}
			}
		}

		if reader.Templates() > 256 {
			t.Errorf("%d templates are held", reader.Templates())
		}
	})
}
