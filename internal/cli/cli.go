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
	errNoMetricsURL   = errors.New("--metrics-url is empty")
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
	)

	set := flag.NewFlagSet("collector", flag.ContinueOnError)
	set.SetOutput(stderr)
	set.Var(&names, "enable", "the plugins to run, by name, comma-separated; may be repeated")
	set.StringVar(&metricsURL, "metrics-url", "", "the metrics store: VictoriaMetrics' scheme and host")

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
	if err == nil && metricsURL == "" {
		err = errNoMetricsURL
	}

	if err != nil {
		fmt.Fprintln(stderr, "collector:", err)

		return ExitUsage
	}

	metrics, err := victoria.NewMetrics(
		&http.Client{Transport: network.NewTransport(), Timeout: storeTimeout},
		metricsURL,
	)
	if err != nil {
		fmt.Fprintln(stderr, "collector:", err)

		return ExitUsage
	}

	if err := collect(ctx, chosen, metrics); err != nil {
		fmt.Fprintln(stderr, "collector:", err)

		return ExitError
	}

	return ExitOK
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
func collect(ctx context.Context, plugins []plugin.Plugin, metrics *victoria.Metrics) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wait  sync.WaitGroup
		once  sync.Once
		first error
	)

	for _, one := range plugins {
		wait.Go(func() {
			err := one.Run(ctx, plugin.Output{Metrics: metrics.For(one.Name())})
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
