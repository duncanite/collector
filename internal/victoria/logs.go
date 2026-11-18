package victoria

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/duncanite/collector/internal/plugin"
)

// insertPath is VictoriaLogs' ingestion API for JSON lines.
const insertPath = "/insert/jsonline"

// The fields VictoriaLogs is told to read a record's time and message
// from, and the one a record's severity is written under.
const (
	timeField     = "_time"
	messageField  = "_msg"
	severityField = "severity_text"
)

// own is how many names of a line are not the record's fields: the time,
// the message, the severity and the job.
const own = 4

// ErrLogsRefused is the store answering a write with anything but success.
var ErrLogsRefused = errors.New("the logs store refused the write")

// Logs writes records to one VictoriaLogs. A write is one request:
// nothing is batched, queued or tried again.
type Logs struct {
	client   *http.Client
	endpoint *url.URL
}

// NewLogs returns a writer to the VictoriaLogs at base, its scheme and
// host, through client.
func NewLogs(client *http.Client, base string) (*Logs, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("the logs store's address: %w", err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("the logs store's address: %w: %q", errNoHost, base)
	}

	return &Logs{client: client, endpoint: parsed.JoinPath(insertPath)}, nil
}

// For returns the writer a plugin is given: every record it writes carries
// the plugin's name as its job.
func (l *Logs) For(job string) plugin.LogWriter {
	return &jobLogs{logs: l, job: job}
}

type jobLogs struct {
	logs *Logs
	job  string
}

// Write sends records in one request, one JSON object a line, and reports
// a store that did not take them; the records are not kept.
func (w *jobLogs) Write(ctx context.Context, records []plugin.Record) error {
	var body bytes.Buffer

	for _, record := range records {
		line, err := json.Marshal(w.line(record))
		if err != nil {
			return fmt.Errorf("writing logs: %w", err)
		}

		body.Write(line)
		body.WriteByte('\n')
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, w.address(records), &body)
	if err != nil {
		return fmt.Errorf("writing logs: %w", err)
	}

	request.Header.Set("Content-Type", "application/stream+json")

	response, err := w.logs.client.Do(request)
	if err != nil {
		return fmt.Errorf("writing logs: %w", err)
	}

	defer func() { _ = response.Body.Close() }()

	// The body is read so the connection can be used again.
	_, _ = io.Copy(io.Discard, response.Body)

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: %s", ErrLogsRefused, response.Status)
	}

	return nil
}

// address is where records go: the store's ingestion API, told which
// fields hold the time and the message, and which make a stream: the job,
// and what the records themselves name.
func (w *jobLogs) address(records []plugin.Record) string {
	stream := []string{jobLabel}

	for _, record := range records {
		for _, name := range record.Stream {
			if !slices.Contains(stream, name) {
				stream = append(stream, name)
			}
		}
	}

	endpoint := *w.logs.endpoint
	endpoint.RawQuery = url.Values{
		"_time_field":    {timeField},
		"_msg_field":     {messageField},
		"_stream_fields": {strings.Join(stream, ",")},
	}.Encode()

	return endpoint.String()
}

// line is a record as the one flat object VictoriaLogs takes: its fields,
// then the names the store reads itself, which a field cannot take over.
func (w *jobLogs) line(record plugin.Record) map[string]string {
	line := make(map[string]string, len(record.Fields)+own)

	for _, field := range record.Fields {
		line[field.Name] = field.Value
	}

	line[timeField] = record.Time.UTC().Format(time.RFC3339Nano)
	line[messageField] = record.Body
	line[jobLabel] = w.job

	if record.Severity != "" {
		line[severityField] = record.Severity
	}

	return line
}
