// Package arris is the plugin for an Arris SURFboard cable modem: on a
// timer it logs in, reads the modem's status pages, and writes what they
// say of the connection as metrics.
package arris

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/duncanite/go-arris/sb8200"

	"github.com/duncanite/collector/internal/plugin"
)

// name is what a deployment enables the plugin by.
const name = "arris"

// passwordVar holds the modem's password; it is never a flag, so never in
// a process list or a container's arguments.
const passwordVar = "ARRIS_PASSWORD" // #nosec G101 -- the variable's name, not a credential

// timeout bounds one call to the modem; it answers a page in under a
// second. readTimeout bounds a whole read: the login and the two pages.
const (
	timeout     = 30 * time.Second
	readTimeout = 3 * timeout
)

var (
	errNoURL         = errors.New("--arris.url is empty")
	errNoFingerprint = errors.New("--arris.fingerprint is empty")
	errNoPassword    = errors.New(passwordVar + " is empty")
	errNoInterval    = errors.New("--arris.interval is not above zero")
)

// Plugin polls one modem.
type Plugin struct {
	url         string
	username    string
	fingerprint string
	interval    time.Duration
}

// New returns the plugin, to be configured by its flags.
func New() *Plugin { return &Plugin{} }

// Name is "arris".
func (*Plugin) Name() string { return name }

// Flags adds the modem's address, account, certificate and polling
// interval. The password comes from ARRIS_PASSWORD.
func (p *Plugin) Flags(set *flag.FlagSet) {
	set.StringVar(&p.url, "arris.url", "", "the modem's page: scheme and host")
	set.StringVar(&p.username, "arris.username", "admin", "the modem's administrator account")
	set.StringVar(&p.fingerprint, "arris.fingerprint", "",
		"SHA-256 of the modem's certificate, hex, pinned in place of the system roots")
	set.DurationVar(&p.interval, "arris.interval", time.Minute, "how often the modem is read")
}

// Run reads the modem now and then every interval, until ctx ends. A read
// that fails is logged and written as arris_up 0; the next one comes at
// its time, none is tried again sooner.
func (p *Plugin) Run(ctx context.Context, out plugin.Output) error {
	password := os.Getenv(passwordVar)

	switch {
	case p.url == "":
		return errNoURL
	case p.fingerprint == "":
		return errNoFingerprint
	case password == "":
		return errNoPassword
	case p.interval <= 0:
		return errNoInterval
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		p.poll(ctx, out, password)

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// poll reads the modem once and writes what it read, or that it could not.
// A read that has begun is finished even when ctx ends in the middle of
// it: a login the modem took and never saw logged out leaves a session on
// the modem, which nothing here could close afterwards.
func (p *Plugin) poll(ctx context.Context, out plugin.Output, password string) {
	now := time.Now()

	reading, cancel := context.WithTimeout(context.WithoutCancel(ctx), readTimeout)
	samples, err := p.read(reading, password, now)

	cancel()

	if ctx.Err() != nil {
		return
	}

	if err != nil {
		slog.WarnContext(ctx, "the modem was not read", "plugin", name, "error", err)

		samples = []plugin.Sample{{Name: "arris_up", Value: 0, Time: now}}
	}

	if err := out.Metrics.Write(ctx, samples); err != nil && ctx.Err() == nil {
		slog.WarnContext(ctx, "the modem's metrics were not stored and are lost", "plugin", name, "error", err)
	}
}

// read logs in, reads the two pages and logs out, whatever the pages
// gave, so no session of ours is left on the modem.
func (p *Plugin) read(ctx context.Context, password string, now time.Time) ([]plugin.Sample, error) {
	client, err := sb8200.HTTPClient(p.fingerprint, false, timeout)
	if err != nil {
		return nil, fmt.Errorf("the modem's certificate: %w", err)
	}

	session, err := sb8200.Login(ctx, client, p.url, p.username, password)
	if err != nil {
		return nil, fmt.Errorf("logging in: %w", err)
	}

	defer func() {
		// Under a time of its own: ctx spent on the pages would stop the
		// logout before it left.
		leaving, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()

		_ = session.Logout(leaving)
	}()

	info, err := session.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the information page: %w", err)
	}

	status, err := session.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the status page: %w", err)
	}

	return samples(info, status, now), nil
}

// samples is the two pages as series, all at the time of the read.
func samples(info *sb8200.Info, status *sb8200.Status, now time.Time) []plugin.Sample {
	sample := func(metric string, value float64, labels ...plugin.Label) plugin.Sample {
		return plugin.Sample{Name: metric, Labels: labels, Value: value, Time: now}
	}

	out := []plugin.Sample{
		sample("arris_up", 1),
		sample("arris_uptime_seconds", info.Uptime.Seconds()),
		sample("arris_info", 1,
			plugin.Label{Name: "specification", Value: info.Specification},
			plugin.Label{Name: "hardware", Value: info.Hardware},
			plugin.Label{Name: "software", Value: info.Software},
		),
	}

	for _, channel := range status.Downstream {
		labels := []plugin.Label{
			{Name: "channel", Value: strconv.Itoa(channel.ID)},
			{Name: "modulation", Value: channel.Modulation},
		}

		out = append(out,
			sample("arris_downstream_locked", flag01(channel.Locked), labels...),
			sample("arris_downstream_frequency_hertz", float64(channel.Frequency), labels...),
			sample("arris_downstream_power_dbmv", channel.Power, labels...),
			sample("arris_downstream_snr_decibels", channel.SNR, labels...),
			sample("arris_downstream_corrected_codewords_total", float64(channel.Corrected), labels...),
			sample("arris_downstream_uncorrectable_codewords_total", float64(channel.Uncorrectable), labels...),
		)
	}

	for _, channel := range status.Upstream {
		labels := []plugin.Label{
			{Name: "channel", Value: strconv.Itoa(channel.ID)},
			{Name: "type", Value: channel.Type},
		}

		out = append(out,
			sample("arris_upstream_locked", flag01(channel.Locked), labels...),
			sample("arris_upstream_frequency_hertz", float64(channel.Frequency), labels...),
			sample("arris_upstream_width_hertz", float64(channel.Width), labels...),
			sample("arris_upstream_power_dbmv", channel.Power, labels...),
		)
	}

	return out
}

func flag01(set bool) float64 {
	if set {
		return 1
	}

	return 0
}
