package unifisyslog_test

import (
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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

func FuzzParse(f *testing.F) {
	for _, datagram := range datagrams(f) {
		f.Add([]byte(strings.TrimSuffix(datagram, `\n`) + "\n"))
	}

	received, location := when(f)

	f.Fuzz(func(t *testing.T, datagram []byte) {
		record := unifisyslog.Parse(datagram, sender, received, location)

		if !utf8.ValidString(record.Body) {
			t.Errorf("a body that is not UTF-8: %q", record.Body)
		}

		if record.Time.IsZero() {
			t.Error("a record with no time")
		}

		for _, field := range record.Fields {
			if field.Name == "" || field.Value == "" || !utf8.ValidString(field.Name) ||
				!utf8.ValidString(field.Value) {
				t.Errorf("a field that is empty or not UTF-8: %q = %q", field.Name, field.Value)
			}
		}
	})
}
