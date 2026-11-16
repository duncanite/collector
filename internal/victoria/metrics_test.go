package victoria_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/duncanite/collector/internal/plugin"
	"github.com/duncanite/collector/internal/victoria"
)

func TestASampleIsOneLineOfTheTextFormat(t *testing.T) {
	t.Parallel()

	var path, body string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		path, body = r.URL.Path, string(data)

		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	metrics, err := victoria.NewMetrics(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	at := time.UnixMilli(1700000000123)

	err = metrics.For("probe").Write(t.Context(), []plugin.Sample{
		{Name: "probe_value", Value: 1.5, Time: at},
		{
			Name:   "probe_info",
			Labels: []plugin.Label{{Name: "text", Value: "a \"quoted\" back\\slash\nand a line"}},
			Value:  1,
			Time:   at,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := "probe_value{job=\"probe\"} 1.5 1700000000123\n" +
		"probe_info{job=\"probe\",text=\"a \\\"quoted\\\" back\\\\slash\\nand a line\"} 1 1700000000123\n"

	if path != "/api/v1/import/prometheus" || body != want {
		t.Errorf("the store was sent, at %q:\n%s\nwant:\n%s", path, body, want)
	}
}

func TestAStoreThatRefusesIsAnError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no room", http.StatusInsufficientStorage)
	}))
	t.Cleanup(server.Close)

	metrics, err := victoria.NewMetrics(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	err = metrics.For("probe").Write(t.Context(), []plugin.Sample{{Name: "probe_value", Value: 1, Time: time.Now()}})
	if err == nil {
		t.Fatal("a refused write returned no error")
	}
}
