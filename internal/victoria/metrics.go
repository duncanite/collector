// Package victoria writes to the stores: VictoriaMetrics' import API, in
// the Prometheus text format.
package victoria

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/duncanite/collector/internal/plugin"
)

// importPath is VictoriaMetrics' import API for the Prometheus text format.
const importPath = "/api/v1/import/prometheus"

// jobLabel names the plugin a sample came from, on every sample.
const jobLabel = "job"

// ErrRefused is the store answering a write with anything but success.
var ErrRefused = errors.New("the metrics store refused the write")

// Metrics writes samples to one VictoriaMetrics. A write is one request:
// nothing is batched, queued or tried again.
type Metrics struct {
	client   *http.Client
	endpoint string
}

// NewMetrics returns a writer to the VictoriaMetrics at base, its scheme
// and host, through client.
func NewMetrics(client *http.Client, base string) (*Metrics, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("the metrics store's address: %w", err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("the metrics store's address: %w: %q", errNoHost, base)
	}

	return &Metrics{client: client, endpoint: parsed.JoinPath(importPath).String()}, nil
}

var errNoHost = errors.New("no scheme or no host")

// For returns the writer a plugin is given: every sample it writes carries
// the plugin's name as its job.
func (m *Metrics) For(job string) plugin.MetricWriter {
	return &jobWriter{metrics: m, job: job}
}

type jobWriter struct {
	metrics *Metrics
	job     string
}

// Write sends samples in one request and reports a store that did not take
// them; the samples are not kept.
func (w *jobWriter) Write(ctx context.Context, samples []plugin.Sample) error {
	var body strings.Builder

	for _, sample := range samples {
		writeSample(&body, w.job, sample)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		w.metrics.endpoint,
		strings.NewReader(body.String()),
	)
	if err != nil {
		return fmt.Errorf("writing metrics: %w", err)
	}

	response, err := w.metrics.client.Do(request)
	if err != nil {
		return fmt.Errorf("writing metrics: %w", err)
	}

	defer func() { _ = response.Body.Close() }()

	// The body is read so the connection can be used again.
	_, _ = io.Copy(io.Discard, response.Body)

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: %s", ErrRefused, response.Status)
	}

	return nil
}

// writeSample writes one line of the text format: the name, its labels
// with the job first, the value, and the time in milliseconds.
func writeSample(out *strings.Builder, job string, sample plugin.Sample) {
	out.WriteString(sample.Name)
	out.WriteByte('{')
	writeLabel(out, plugin.Label{Name: jobLabel, Value: job})

	for _, label := range sample.Labels {
		out.WriteByte(',')
		writeLabel(out, label)
	}

	out.WriteString("} ")
	out.WriteString(strconv.FormatFloat(sample.Value, 'g', -1, 64))
	out.WriteByte(' ')
	out.WriteString(strconv.FormatInt(sample.Time.UnixMilli(), 10))
	out.WriteByte('\n')
}

// labelEscaper escapes what the text format gives a meaning to inside a
// label's value.
//
//nolint:gochecknoglobals // a replacer is built once
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func writeLabel(out *strings.Builder, label plugin.Label) {
	out.WriteString(label.Name)
	out.WriteString(`="`)
	out.WriteString(labelEscaper.Replace(label.Value))
	out.WriteByte('"')
}
