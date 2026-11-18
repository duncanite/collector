package victoria

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/duncanite/collector/internal/plugin"
)

// Where each store takes OpenTelemetry's own requests.
const (
	metricsOTLP = "/opentelemetry/v1/metrics"
	logsOTLP    = "/insert/opentelemetry/v1/logs"
)

// maxAnswer is how much of a store's answer is handed back: a success is
// empty, and a refusal says why in a line.
const maxAnswer = 64 << 10

// Relay takes OpenTelemetry requests to one store as they came, unread.
type Relay struct {
	client   *http.Client
	endpoint string
}

// NewMetricsRelay returns a relay to the VictoriaMetrics at base, its
// scheme and host, through client.
func NewMetricsRelay(client *http.Client, base string) (*Relay, error) {
	return newRelay(client, base, metricsOTLP)
}

// NewLogsRelay returns a relay to the VictoriaLogs at base, its scheme
// and host, through client.
func NewLogsRelay(client *http.Client, base string) (*Relay, error) {
	return newRelay(client, base, logsOTLP)
}

func newRelay(client *http.Client, base, path string) (*Relay, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("the store's address: %w", err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("the store's address: %w: %q", errNoHost, base)
	}

	return &Relay{client: client, endpoint: parsed.JoinPath(path).String()}, nil
}

// Relay sends one request on, its body streamed and never held, and
// returns what the store answered, whatever it answered: a refusal is the
// store's to explain and the sender's to hear. The error is the store not
// reached, or the body not read to its end.
func (r *Relay) Relay(ctx context.Context, sent plugin.Request) (plugin.Answer, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, sent.Body)
	if err != nil {
		return plugin.Answer{}, fmt.Errorf("relaying to the store: %w", err)
	}

	request.ContentLength = sent.Length

	if sent.ContentType != "" {
		request.Header.Set("Content-Type", sent.ContentType)
	}

	if sent.ContentEncoding != "" {
		request.Header.Set("Content-Encoding", sent.ContentEncoding)
	}

	response, err := r.client.Do(request)
	if err != nil {
		return plugin.Answer{}, fmt.Errorf("relaying to the store: %w", err)
	}

	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxAnswer))
	if err != nil {
		return plugin.Answer{}, fmt.Errorf("reading the store's answer: %w", err)
	}

	// What is left is read so the connection can be used again.
	_, _ = io.Copy(io.Discard, response.Body)

	return plugin.Answer{
		Status:      response.StatusCode,
		ContentType: response.Header.Get("Content-Type"),
		Body:        body,
	}, nil
}
