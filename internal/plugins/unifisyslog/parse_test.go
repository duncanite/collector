package unifisyslog_test

import (
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/forkcloser/xos"

	"github.com/duncanite/collector/internal/plugin"
	"github.com/duncanite/collector/internal/plugins/unifisyslog"
)

//nolint:gochecknoglobals // the one flag of the test binary
var update = flag.Bool("update", false, "rewrite the golden files from what Parse returns")

// sender is where the fixtures' datagrams are said to come from.
const sender = "192.0.2.1"

// The fixtures' lines are read as received on 15 November 2026, late in
// the evening in Los Angeles, the zone their timestamps are in.
func when(tb testing.TB) (time.Time, *time.Location) {
	tb.Helper()

	location, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		tb.Fatal(err)
	}

	return time.Date(2026, time.November, 15, 20, 0, 0, 0, location), location
}

// datagrams reads a fixture file: its lines, less the blank ones and the
// comments. A line is written with the line feed that ends its datagram
// spelled out, \n, which also keeps a space before it from being trimmed
// away by an editor.
func datagrams(tb testing.TB) []string {
	tb.Helper()

	data, err := xos.ReadFile(filepath.Join("testdata", "unifi.syslog"))
	if err != nil {
		tb.Fatal(err)
	}

	var lines []string

	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lines = append(lines, line)
	}

	return lines
}

// render writes a record the way the golden file holds it: the datagram it
// came from, then what the store is sent.
func render(out *strings.Builder, datagram string, record plugin.Record) {
	fmt.Fprintf(out, "<<< %s\n", datagram)
	fmt.Fprintf(out, "time      %s\n", record.Time.UTC().Format("2006-01-02T15:04:05.000Z"))
	fmt.Fprintf(out, "severity  %s\n", record.Severity)
	fmt.Fprintf(out, "body      %q\n", record.Body)

	fields := slices.Clone(record.Fields)
	slices.SortFunc(fields, func(a, b plugin.Field) int { return strings.Compare(a.Name, b.Name) })

	for _, field := range fields {
		fmt.Fprintf(out, "  %-26s %q\n", field.Name, field.Value)
	}

	out.WriteByte('\n')
}

func TestTheShapesUniFiSends(t *testing.T) {
	t.Parallel()

	received, location := when(t)

	var got strings.Builder

	for _, datagram := range datagrams(t) {
		payload := strings.TrimSuffix(datagram, `\n`) + "\n"

		render(&got, datagram, unifisyslog.Parse([]byte(payload), sender, received, location))
	}

	golden := filepath.Join("testdata", "unifi.golden")

	// One line feed ends the file, where every record ends with two.
	parsed := strings.TrimRight(got.String(), "\n") + "\n"

	if *update {
		if err := xos.WriteFile(golden, []byte(parsed), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	want, err := xos.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}

	if parsed != string(want) {
		t.Errorf("Parse returned:\n%s\nwant, from %s:\n%s", parsed, golden, want)
	}
}

func TestALineNobodyMappedIsKeptWhole(t *testing.T) {
	t.Parallel()

	received, location := when(t)

	for name, test := range map[string]struct {
		line string
		body string
		at   time.Time
		host string
	}{
		"no header at all":         {"hello", "hello", received, ""},
		"a priority and no time":   {"<14>hello there", "<14>hello there", received, ""},
		"a time and no host":       {"<14>Nov 15 15:54:49 ", "<14>Nov 15 15:54:49", received, ""},
		"a host and a bare text":   {"<14>Nov 15 15:54:49 Gateway something happened", "something happened", time.Date(2026, time.November, 15, 15, 54, 49, 0, location), "Gateway"},
		"a priority out of range":  {"<999>Nov 15 15:54:49 Gateway x: y", "<999>Nov 15 15:54:49 Gateway x: y", received, ""},
		"a CEF head and no header": {"Nov 15 15:54:49 Gateway CEF:0|Ubiquiti|only", "Nov 15 15:54:49 Gateway CEF:0|Ubiquiti|only", time.Date(2026, time.November, 15, 15, 54, 49, 0, location), "Gateway"},
		"December read in January": {"<14>Dec 31 23:59:58 Gateway x: late", "late", time.Date(2025, time.December, 31, 23, 59, 58, 0, location), "Gateway"},
	} {
		at := received
		if name == "December read in January" {
			at = time.Date(2026, time.January, 1, 0, 0, 5, 0, location)
		}

		record := unifisyslog.Parse([]byte(test.line), sender, at, location)

		host := ""

		for _, field := range record.Fields {
			if field.Name == "host.name" {
				host = field.Value
			}
		}

		if record.Body != test.body || !record.Time.Equal(test.at) || host != test.host {
			t.Errorf("%s: body %q, time %s, host %q; want %q, %s, %q",
				name, record.Body, record.Time, host, test.body, test.at, test.host)
		}
	}
}

// field is the value a record holds under name, or none.
func field(record plugin.Record, name string) string {
	for _, held := range record.Fields {
		if held.Name == name {
			return held.Value
		}
	}

	return ""
}

func TestALineThatClaimsAnotherDayIsDatedByItsReading(t *testing.T) {
	t.Parallel()

	received, location := when(t)
	leap := time.Date(2028, time.February, 29, 12, 0, 0, 0, location)

	for name, test := range map[string]struct {
		line     string
		received time.Time
		at       time.Time
	}{
		"the same evening": {
			"<14>Nov 15 19:59:58 Gateway x: y", received,
			time.Date(2026, time.November, 15, 19, 59, 58, 0, location),
		},
		"a clock some hours ahead": {
			"<14>Nov 16 06:00:00 Gateway x: y", received,
			time.Date(2026, time.November, 16, 6, 0, 0, 0, location),
		},
		"two days ahead":               {"<14>Nov 17 20:00:01 Gateway x: y", received, received},
		"two days behind":              {"<14>Nov 13 19:59:59 Gateway x: y", received, received},
		"a clock never set":            {"<14>Jan  1 00:00:12 Gateway x: y", received, received},
		"a day its year does not have": {"<14>Feb 29 12:00:00 Gateway x: y", received, received},
		"that day, in a year that has it": {
			"<14>Feb 29 11:59:00 Gateway x: y", leap,
			time.Date(2028, time.February, 29, 11, 59, 0, 0, location),
		},
		"January read in December": {
			"<14>Jan  1 00:00:03 Gateway x: y", time.Date(2026, time.December, 31, 23, 59, 58, 0, location),
			time.Date(2027, time.January, 1, 0, 0, 3, 0, location),
		},
	} {
		record := unifisyslog.Parse([]byte(test.line), sender, test.received, location)

		// Whatever its time, the rest of the line is read.
		if !record.Time.Equal(test.at) || record.Body != "y" || field(record, "host.name") != "Gateway" {
			t.Errorf("%s: time %s, body %q, host %q; want %s, \"y\", \"Gateway\"",
				name, record.Time, record.Body, field(record, "host.name"), test.at)
		}
	}
}

func TestAnEventsOwnTimeIsTakenOnlyNearItsReading(t *testing.T) {
	t.Parallel()

	received, location := when(t)
	header := time.Date(2026, time.November, 15, 19, 59, 0, 0, location)

	const head = "Nov 15 19:59:00 Gateway CEF:0|Ubiquiti|UniFi Network|1.2.3|400|Something|1|"

	for name, test := range map[string]struct {
		claimed string
		at      time.Time
	}{
		"to the millisecond": {"2026-11-16T03:59:00.250Z", header.Add(250 * time.Millisecond)},
		"the zero time":      {"0001-01-01T00:00:00Z", header},
		"the epoch":          {"1970-01-01T00:00:00Z", header},
		"the end of time":    {"9999-12-31T23:59:59Z", header},
		"two days ahead":     {"2026-11-18T04:00:00Z", header},
		"what is not a time": {"yesterday", header},
	} {
		record := unifisyslog.Parse(
			[]byte(head+"UNIFIutcTime="+test.claimed+" msg=It happened."),
			sender,
			received,
			location,
		)

		// What the event claims stays readable in its field.
		if !record.Time.Equal(test.at) || field(record, "cef.extensions.UNIFIutcTime") != test.claimed ||
			record.Body != "It happened." {
			t.Errorf("%s: time %s, field %q, body %q; want %s",
				name, record.Time, field(record, "cef.extensions.UNIFIutcTime"), record.Body, test.at)
		}
	}
}

func TestAnEventWithMoreExtensionsThanTheConsoleWritesKeepsItsText(t *testing.T) {
	t.Parallel()

	received, location := when(t)

	const head = "Nov 15 19:59:00 Gateway CEF:0|Ubiquiti|UniFi Network|1.2.3|400|Something|1|"

	event := func(extensions int) (string, plugin.Record) {
		var text strings.Builder

		text.WriteString(head + "msg=It happened.")

		for index := 1; index < extensions; index++ {
			fmt.Fprintf(&text, " key%d=value", index)
		}

		return text.String(), unifisyslog.Parse([]byte(text.String()), sender, received, location)
	}

	extensions := func(record plugin.Record) int {
		count := 0

		for _, held := range record.Fields {
			if strings.HasPrefix(held.Name, "cef.extensions.") {
				count++
			}
		}

		return count
	}

	// As many as are taken: the sentence is the body, the rest are fields.
	if _, record := event(64); record.Body != "It happened." || extensions(record) != 63 {
		t.Errorf("64 extensions: body %q and %d fields", record.Body, extensions(record))
	}

	// One more, and ten thousand: the text stays whole, and the fields stop.
	for _, count := range []int{65, 10000} {
		text, record := event(count)

		if record.Body != text || extensions(record) != 63 {
			t.Errorf("%d extensions: %d fields, and a body of %d bytes for a text of %d",
				count, extensions(record), len(record.Body), len(text))
		}
	}
}

func TestWhatAPrinterWouldObeyIsReplaced(t *testing.T) {
	t.Parallel()

	received, location := when(t)

	record := unifisyslog.Parse(
		[]byte("<14>Nov 15 19:59:00 Ga\x1b[2Jte\x07 prog[7]: one\ttwo\x7f\u0085\nthr\x00ee\r"),
		sender, received, location,
	)

	// The tab and the line feed are text; the line feed and the carriage
	// return that end a datagram are not part of it.
	if record.Body != "one\ttwo\uFFFD\uFFFD\nthr\uFFFDee" {
		t.Errorf("body %q", record.Body)
	}

	if host := field(record, "host.name"); host != "Ga\uFFFD[2Jte\uFFFD" {
		t.Errorf("host %q", host)
	}
}

func TestARecordIsGroupedByItsSenderAndNothingOfTheLine(t *testing.T) {
	t.Parallel()

	received, location := when(t)

	for _, datagram := range datagrams(t) {
		record := unifisyslog.Parse([]byte(strings.TrimSuffix(datagram, `\n`)), sender, received, location)

		if !slices.Equal(record.Stream, []string{"network.peer.address"}) ||
			field(record, "network.peer.address") != sender {
			t.Errorf("stream %q, sender %q, for %s", record.Stream, field(record, "network.peer.address"), datagram)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, datagram := range datagrams(f) {
		f.Add([]byte(strings.TrimSuffix(datagram, `\n`) + "\n"))
	}

	// What a sender that is no device might write.
	for _, datagram := range []string{
		"Nov 15 19:59:00 Gateway CEF:0|a|b|c|d|e|1|UNIFIutcTime=0001-01-01T00:00:00Z msg=x",
		"Nov 15 19:59:00 Gateway CEF:0|a|b|c|d|e|1|UNIFIutcTime=9999-12-31T23:59:59Z",
		"<14>Feb 29 12:00:00 Gateway x: y",
		"<14>Jan  1 00:00:12 Ga\x1b[2Jte prog\x00[7]: one\x7f",
		"Nov 15 19:59:00 Gateway CEF:0|a|b|c|d|e|1|" + strings.Repeat("k=v ", 200),
	} {
		f.Add([]byte(datagram))
	}

	received, location := when(f)

	f.Fuzz(func(t *testing.T, datagram []byte) {
		record := unifisyslog.Parse(datagram, sender, received, location)

		if !utf8.ValidString(record.Body) {
			t.Errorf("a body that is not UTF-8: %q", record.Body)
		}

		// Its reading, or within a day of it: nothing a line says moves it
		// further.
		if apart := record.Time.Sub(received); apart > 24*time.Hour || apart < -24*time.Hour {
			t.Errorf("a record dated %s, read at %s", record.Time, received)
		}

		if obeyed(record.Body) {
			t.Errorf("a body a printer would obey: %q", record.Body)
		}

		// The header's dozen, and the extensions that are taken.
		if len(record.Fields) > 96 {
			t.Errorf("a record of %d fields", len(record.Fields))
		}

		for _, field := range record.Fields {
			if field.Name == "" || field.Value == "" || !utf8.ValidString(field.Name) ||
				!utf8.ValidString(field.Value) {
				t.Errorf("a field that is empty or not UTF-8: %q = %q", field.Name, field.Value)
			}

			if obeyed(field.Name) || obeyed(field.Value) {
				t.Errorf("a field a printer would obey: %q = %q", field.Name, field.Value)
			}
		}
	})
}

// obeyed reports whether text holds a control character other than the
// tab and the line feed.
func obeyed(text string) bool {
	return strings.ContainsFunc(text, func(char rune) bool {
		return unicode.IsControl(char) && char != '\t' && char != '\n'
	})
}
