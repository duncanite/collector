// Package plugin is what a source of telemetry is to the collector: every
// source is compiled in, and a deployment names the ones it runs.
package plugin

import (
	"context"
	"flag"
	"time"
)

// A Plugin is one source: something the collector listens to or goes and
// asks. It is off until a deployment enables it by name.
type Plugin interface {
	// Name is what a deployment enables the plugin by, and the prefix of
	// its flags.
	Name() string
	// Flags adds the plugin's own flags to set, each named "<name>.<flag>".
	// It is called for every plugin, enabled or not, so that the command
	// line of one deployment parses on a build that holds them all.
	Flags(set *flag.FlagSet)
	// Run collects until ctx ends and hands what it collects to out. It
	// returns an error only for what a deployment got wrong, a missing
	// address or credential, and nil when ctx ends: a source that does not
	// answer is reported through out and logged, and Run goes on.
	Run(ctx context.Context, out Output) error
}

// Output is where a plugin hands over what it collected. Nothing is kept:
// a write the store refuses is lost, and says so by its error. A store the
// deployment did not name is nil here, and a plugin that needs it says so.
type Output struct {
	Metrics MetricWriter
	Logs    LogWriter
}

// LogWriter takes records to the logs store.
type LogWriter interface {
	// Write sends records in one request. An error means the store did
	// not take them and they are gone.
	Write(ctx context.Context, records []Record) error
}

// Record is one log line: when it happened, how severe it is, what it
// says, and what else is known of it.
type Record struct {
	Time time.Time
	// Severity is the syslog keyword: "info", "warning", "err"; empty when
	// the source gave none.
	Severity string
	Body     string
	Fields   []Field
	// Stream names the fields the store groups records by, besides the
	// plugin's own name: what tells one source of lines from another. They
	// are to take few values, and none that whoever writes the lines
	// chooses freely: a store keeps something for every stream it has
	// seen.
	Stream []string
}

// Field is one name and value of a record. The names are OpenTelemetry's
// where it has one: host.name, service.name, process.pid.
type Field struct {
	Name  string
	Value string
}

// MetricWriter takes samples to the metrics store.
type MetricWriter interface {
	// Write sends samples in one request. An error means the store did
	// not take them and they are gone.
	Write(ctx context.Context, samples []Sample) error
}

// Sample is one value of one series at one time.
type Sample struct {
	Name   string
	Labels []Label
	Value  float64
	Time   time.Time
}

// Label is one name and value of a series.
type Label struct {
	Name  string
	Value string
}
