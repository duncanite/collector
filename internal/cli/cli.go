// Package cli is the collector's command line: the stores' addresses, the
// plugins a deployment enables, and each plugin's own flags. Every plugin
// is compiled in; the ones named by --enable run.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mycophonic/primordium/network"

	"github.com/duncanite/collector/internal/plugin"
	"github.com/duncanite/collector/internal/victoria"
)

// Exit statuses.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

// storeTimeout bounds one write to a store.
const storeTimeout = 30 * time.Second

var (
	errNothingEnabled = errors.New("no plugin is enabled: name some with --enable")
	errUnknownPlugin  = errors.New("no such plugin")
)

// enabled is the --enable flag: plugin names, comma-separated, given once
// or several times.
type enabled []string

func (e *enabled) String() string { return strings.Join(*e, ",") }

func (e *enabled) Set(value string) error {
	for name := range strings.SplitSeq(value, ",") {
		if name = strings.TrimSpace(name); name != "" && !slices.Contains(*e, name) {
			*e = append(*e, name)
		}
	}

	return nil
}

// Run parses args, runs the enabled plugins among plugins until ctx ends
// or one of them refuses its configuration, and returns the exit status.
// Errors and usage go to stderr.
func Run(ctx context.Context, args []string, stderr io.Writer, plugins ...plugin.Plugin) int {
	var (
		names      enabled
		metricsURL string
		logsURL    string
	)

	set := flag.NewFlagSet("collector", flag.ContinueOnError)
	set.SetOutput(stderr)
	set.Var(&names, "enable", "the plugins to run, by name, comma-separated; may be repeated")
	set.StringVar(&metricsURL, "metrics-url", "", "the metrics store: VictoriaMetrics' scheme and host")
	set.StringVar(&logsURL, "logs-url", "", "the logs store: VictoriaLogs' scheme and host")

	for _, one := range plugins {
		one.Flags(set)
	}

	if err := set.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}

		return ExitUsage
	}

	chosen, err := choose(names, plugins)
	if err != nil {
		fmt.Fprintln(stderr, "collector:", err)

		return ExitUsage
	}

	out, err := stores(metricsURL, logsURL)
	if err != nil {
		fmt.Fprintln(stderr, "collector:", err)

		return ExitUsage
	}

	if err := collect(ctx, chosen, out); err != nil {
		fmt.Fprintln(stderr, "collector:", err)

		return ExitError
	}

	return ExitOK
}

// outputs is the stores a deployment named; one it did not name is nil,
// and a plugin that needs it refuses to run.
type outputs struct {
	metrics *victoria.Metrics
	logs    *victoria.Logs
}

// stores opens the stores whose addresses are given.
func stores(metricsURL, logsURL string) (outputs, error) {
	var (
		out    outputs
		err    error
		client = &http.Client{Transport: network.NewTransport(), Timeout: storeTimeout}
	)

	if metricsURL != "" {
		if out.metrics, err = victoria.NewMetrics(client, metricsURL); err != nil {
			return outputs{}, fmt.Errorf("--metrics-url: %w", err)
		}
	}

	if logsURL != "" {
		if out.logs, err = victoria.NewLogs(client, logsURL); err != nil {
			return outputs{}, fmt.Errorf("--logs-url: %w", err)
		}
	}

	return out, nil
}

// output is what one plugin is handed: each store the deployment named,
// writing under the plugin's name.
func (out outputs) output(name string) plugin.Output {
	var handed plugin.Output

	if out.metrics != nil {
		handed.Metrics = out.metrics.For(name)
	}

	if out.logs != nil {
		handed.Logs = out.logs.For(name)
	}

	return handed
}

// choose returns the plugins names enable, in the order given.
func choose(names []string, plugins []plugin.Plugin) ([]plugin.Plugin, error) {
	if len(names) == 0 {
		return nil, errNothingEnabled
	}

	chosen := make([]plugin.Plugin, 0, len(names))

	for _, name := range names {
		var named plugin.Plugin

		for _, one := range plugins {
			if one.Name() == name {
				named = one

				break
			}
		}

		if named == nil {
			return nil, fmt.Errorf("%w: %q", errUnknownPlugin, name)
		}

		chosen = append(chosen, named)
	}

	return chosen, nil
}

// collect starts every plugin and waits for them all. The first to return an
// error ends the others, and its error is the one returned.
func collect(ctx context.Context, plugins []plugin.Plugin, out outputs) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wait  sync.WaitGroup
		once  sync.Once
		first error
	)

	for _, one := range plugins {
		wait.Go(func() {
			err := one.Run(ctx, out.output(one.Name()))
			if err == nil {
				return
			}

			once.Do(func() {
				first = fmt.Errorf("%s: %w", one.Name(), err)

				cancel()
			})
		})
	}

	wait.Wait()

	return first
}
