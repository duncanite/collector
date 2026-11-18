// Package otlp is the plugin for the house's own programs that speak
// OpenTelemetry: it listens for their OTLP requests over HTTP and passes
// each on to the store for its signal, unread, and the store's answer back.
//
// Nothing is decoded, kept or tried again: a program whose request the
// store refuses, or that finds the collector gone, hears so and does what
// its own exporter does about it.
package otlp

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/duncanite/collector/internal/plugin"
)

// name is what a deployment enables the plugin by.
const name = "otlp"

// maxBody is the largest request passed on. A body is streamed to the
// store and never held, so this bounds what one sender can push through,
// not what the collector keeps.
const maxBody = 16 << 20

// The server's patience: with a sender that will not finish its headers
// or its body, with a store that will not answer, with a connection that
// says nothing, and with the requests in flight when the collector stops.
const (
	headerTimeout   = 10 * time.Second
	exchangeTimeout = time.Minute
	idleTimeout     = 2 * time.Minute
	stopTimeout     = 10 * time.Second
	maxHeader       = 64 << 10
)

var (
	errNoListen = errors.New("--otlp.listen is empty")
	errNoStore  = errors.New("it relays to the stores and neither --metrics-url nor --logs-url is given")
	errTooLarge = errors.New("the request is larger than the plugin passes on")
)

// Plugin listens on one TCP address.
type Plugin struct {
	listen string
}

// New returns the plugin, to be configured by its flags.
func New() *Plugin { return &Plugin{} }

// Name is "otlp".
func (*Plugin) Name() string { return name }

// Flags adds the address to listen on.
func (p *Plugin) Flags(set *flag.FlagSet) {
	set.StringVar(&p.listen, "otlp.listen", "",
		"the TCP address OTLP over HTTP is taken on: host:port, or :port (4318 is the protocol's own)")
}

// Run serves until ctx ends. /v1/metrics goes to the metrics store and
// /v1/logs to the logs store; a signal whose store the deployment did not
// name, and every other path, is not found.
func (p *Plugin) Run(ctx context.Context, out plugin.Output) error {
	switch {
	case out.MetricsRelay == nil && out.LogsRelay == nil:
		return errNoStore
	case p.listen == "":
		return errNoListen
	}

	var config net.ListenConfig

	listener, err := config.Listen(ctx, "tcp", p.listen)
	if err != nil {
		return fmt.Errorf("--otlp.listen: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/metrics", pass(out.MetricsRelay))
	mux.Handle("/v1/logs", pass(out.LogsRelay))

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: headerTimeout,
		ReadTimeout:       exchangeTimeout,
		WriteTimeout:      exchangeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeader,
		// A request does not outlive the collector's stop by more than
		// the time Shutdown gives it.
		BaseContext: func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}

	served := make(chan error, 1)

	go func() { served <- server.Serve(listener) }()

	select {
	case err = <-served:
		return fmt.Errorf("serving on %s: %w", p.listen, err)
	case <-ctx.Done():
	}

	stopping, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopTimeout)
	defer cancel()

	if err = server.Shutdown(stopping); err != nil {
		// The requests still in flight are cut.
		_ = server.Close()
	}

	return nil
}

// pass is the handler for one signal: a POST's body goes to relay as it
// is, and what relay's store answers goes back.
func pass(relay plugin.Relay) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case relay == nil:
			http.Error(writer, "this collector has no store for the signal", http.StatusNotFound)

			return
		case request.Method != http.MethodPost:
			writer.Header().Set("Allow", http.MethodPost)
			http.Error(writer, "OTLP is sent with POST", http.StatusMethodNotAllowed)

			return
		case request.ContentLength > maxBody:
			http.Error(writer, errTooLarge.Error(), http.StatusRequestEntityTooLarge)

			return
		}

		body := &bounded{from: request.Body, left: maxBody}

		answer, err := relay.Relay(request.Context(), plugin.Request{
			ContentType:     request.Header.Get("Content-Type"),
			ContentEncoding: request.Header.Get("Content-Encoding"),
			Length:          request.ContentLength,
			Body:            body,
		})

		switch {
		case body.over:
			// A body that did not say its length and went past the bound:
			// the store was sent its beginning and no end.
			http.Error(writer, errTooLarge.Error(), http.StatusRequestEntityTooLarge)
		case err != nil:
			slog.WarnContext(request.Context(), "a request was not relayed and is lost",
				"plugin", name, "path", request.URL.Path, "error", err)
			http.Error(writer, "the store was not reached", http.StatusBadGateway)
		default:
			if answer.ContentType != "" {
				writer.Header().Set("Content-Type", answer.ContentType)
			}

			writer.WriteHeader(answer.Status)
			_, _ = writer.Write(answer.Body)
		}
	})
}

// bounded reads from a request's body and stops, with an error, past the
// bound.
type bounded struct {
	from io.Reader
	left int64
	over bool
}

func (b *bounded) Read(into []byte) (int, error) {
	if b.over {
		return 0, errTooLarge
	}

	count, err := b.from.Read(into)

	b.left -= int64(count)
	if b.left < 0 {
		b.over = true

		return 0, errTooLarge
	}

	return count, err //nolint:wrapcheck // the body's own end or error, as it is
}
