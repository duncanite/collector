package cli_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forkcloser/xos"
	"github.com/mycophonic/primordium/network"

	"github.com/duncanite/go-arris/sb8200/sb8200test"
	"github.com/duncanite/go-unifi/console/consoletest"

	"github.com/duncanite/collector/internal/cli"
	"github.com/duncanite/collector/internal/plugins/arris"
	"github.com/duncanite/collector/internal/plugins/unifi"
	"github.com/duncanite/collector/internal/plugins/unifisyslog"
)

// patience bounds every wait on the collector.
const patience = 30 * time.Second

//nolint:gochecknoglobals // the one flag of the test binary
var update = flag.Bool("update", false, "rewrite the golden files from what the collector writes")

// TestMain installs the process default transport app.Main installs, so
// the tests run against the same transport the binary does.
func TestMain(m *testing.M) {
	network.SetDefaults()

	m.Run()
}

// write is one request a store received.
type write struct {
	path  string
	query string
	body  string
}

// store stands for VictoriaMetrics: it keeps the writes it is sent, and
// answers the first `refuse` of them with an error.
type store struct {
	server *httptest.Server
	writes chan write

	mu     sync.Mutex
	refuse int
}

func newStore(t *testing.T, refuse int) *store {
	t.Helper()

	const backlog = 16

	st := &store{writes: make(chan write, backlog), refuse: refuse}

	st.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		st.mu.Lock()
		refused := st.refuse > 0

		if refused {
			st.refuse--
		}
		st.mu.Unlock()

		if refused {
			http.Error(w, "no room", http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}

		st.writes <- write{path: r.URL.Path, query: r.URL.RawQuery, body: string(body)}
	}))
	t.Cleanup(st.server.Close)

	return st
}

// next is the store's next write, or the test's failure.
func (st *store) next(t *testing.T) write {
	t.Helper()

	select {
	case got := <-st.writes:
		return got
	case <-time.After(patience):
		t.Fatal("nothing reached the metrics store")

		return write{}
	}
}

// collector is a run of the command, started by start and ended by stop.
type collector struct {
	cancel context.CancelFunc
	done   chan int
	stderr *bytes.Buffer
}

func start(t *testing.T, args ...string) *collector {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	col := &collector{cancel: cancel, done: make(chan int, 1), stderr: &bytes.Buffer{}}

	go func() { col.done <- cli.Run(ctx, args, col.stderr, arris.New(), unifi.New(), unifisyslog.New()) }()

	t.Cleanup(cancel)

	return col
}

// stop ends the run and returns its exit status and what it printed.
func (col *collector) stop(t *testing.T) (code int, stderr string) {
	t.Helper()

	col.cancel()

	return col.wait(t)
}

// wait is for a run that ends by itself.
func (col *collector) wait(t *testing.T) (code int, stderr string) {
	t.Helper()

	select {
	case code = <-col.done:
		return code, col.stderr.String()
	case <-time.After(patience):
		t.Fatal("the collector did not end")

		return 0, ""
	}
}

// modem starts the stand-in modem and returns it with the flags that
// reach it and the store.
func modem(t *testing.T, st *store, interval string) (*sb8200test.Modem, []string) {
	t.Helper()

	fake := sb8200test.New()
	t.Cleanup(fake.Close)

	return fake, []string{
		"--enable", "arris",
		"--metrics-url", st.server.URL,
		"--arris.url", fake.URL(),
		"--arris.fingerprint", fake.Fingerprint(),
		"--arris.interval", interval,
	}
}

// untimed is a write's lines without the time that ends each.
func untimed(t *testing.T, body string) string {
	t.Helper()

	var out strings.Builder

	for line := range strings.SplitSeq(strings.TrimSuffix(body, "\n"), "\n") {
		cut := strings.LastIndexByte(line, ' ')
		if cut < 0 {
			t.Fatalf("a line with no time: %q", line)
		}

		out.WriteString(line[:cut])
		out.WriteByte('\n')
	}

	return out.String()
}

func TestTheModemReachesTheMetricsStore(t *testing.T) {
	t.Setenv("ARRIS_PASSWORD", sb8200test.Password)

	st := newStore(t, 0)
	fake, args := modem(t, st, "1h")

	col := start(t, args...)
	got := st.next(t)

	if code, stderr := col.stop(t); code != cli.ExitOK {
		t.Fatalf("exit = %d:\n%s", code, stderr)
	}

	if got.path != "/api/v1/import/prometheus" {
		t.Errorf("the write went to %q", got.path)
	}

	if fake.Logins() != 1 || fake.Logouts() != 1 || fake.LoggedIn() {
		t.Errorf(
			"the modem saw %d logins and %d logouts, a session left: %v",
			fake.Logins(),
			fake.Logouts(),
			fake.LoggedIn(),
		)
	}

	golden := filepath.Join("testdata", "arris.golden")
	sent := untimed(t, got.body)

	if *update {
		if err := xos.WriteFile(golden, []byte(sent), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	want, err := xos.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}

	if sent != string(want) {
		t.Errorf("the metrics store was sent:\n%s\nwant, from %s:\n%s", sent, golden, want)
	}
}

func TestAStopInTheMiddleOfAReadLeavesNoSession(t *testing.T) {
	t.Setenv("ARRIS_PASSWORD", sb8200test.Password)

	st := newStore(t, 0)
	fake, args := modem(t, st, "1h")

	col := start(t, args...)

	// Stopped as soon as the modem has taken the login, before the pages
	// are read.
	for deadline := time.Now().Add(patience); fake.Logins() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("the collector never logged in")
		}

		time.Sleep(time.Millisecond)
	}

	if code, stderr := col.stop(t); code != cli.ExitOK {
		t.Fatalf("exit = %d:\n%s", code, stderr)
	}

	if fake.LoggedIn() || fake.Logouts() != fake.Logins() {
		t.Errorf("a session was left on the modem: %d logins, %d logouts", fake.Logins(), fake.Logouts())
	}
}

func TestAModemThatRefusesIsWrittenAsDown(t *testing.T) {
	t.Setenv("ARRIS_PASSWORD", "not the password")

	st := newStore(t, 0)
	_, args := modem(t, st, "1h")

	col := start(t, args...)

	if got := untimed(t, st.next(t).body); got != "arris_up{job=\"arris\"} 0\n" {
		t.Errorf("the metrics store was sent:\n%s", got)
	}

	// The collector goes on: a modem that refuses is not a reason to stop.
	select {
	case code := <-col.done:
		t.Fatalf("the collector ended, exit %d:\n%s", code, col.stderr.String())
	default:
	}

	if code, stderr := col.stop(t); code != cli.ExitOK {
		t.Fatalf("exit = %d:\n%s", code, stderr)
	}
}

func TestAWriteTheStoreRefusesIsLost(t *testing.T) {
	t.Setenv("ARRIS_PASSWORD", sb8200test.Password)

	st := newStore(t, 1)
	fake, args := modem(t, st, "300ms")

	col := start(t, args...)

	first, second := st.next(t), st.next(t)

	// The second write is the next read's, at its time: the refused one was
	// not sent again, so each write has a login of its own behind it.
	if logins := fake.Logins(); logins < 2 {
		t.Errorf("two writes after %d logins: the refused write was sent again", logins)
	}

	if !strings.HasPrefix(first.body, "arris_up{job=\"arris\"} 1 ") ||
		!strings.HasPrefix(second.body, "arris_up{job=\"arris\"} 1 ") {
		t.Errorf("the writes do not start with arris_up 1:\n%s\n%s", first.body, second.body)
	}

	if first.body == second.body {
		t.Error("the second write is the first, byte for byte: it was sent again")
	}

	if code, stderr := col.stop(t); code != cli.ExitOK {
		t.Fatalf("exit = %d:\n%s", code, stderr)
	}
}

func TestWhatADeploymentGetsWrong(t *testing.T) {
	st := newStore(t, 0)
	_, args := modem(t, st, "1h")

	without := func(dropped string) []string {
		out := []string{}

		for index := 0; index < len(args); index += 2 {
			if args[index] != dropped {
				out = append(out, args[index], args[index+1])
			}
		}

		return out
	}

	for name, test := range map[string]struct {
		args     []string
		password string
		code     int
		says     string
	}{
		"nothing enabled":      {without("--enable"), sb8200test.Password, cli.ExitUsage, "no plugin is enabled"},
		"an unknown plugin":    {append(without("--enable"), "--enable", "arris,toaster"), sb8200test.Password, cli.ExitUsage, `no such plugin: "toaster"`},
		"no metrics store":     {without("--metrics-url"), sb8200test.Password, cli.ExitError, "arris: it writes metrics and --metrics-url is empty"},
		"a store with no host": {append(without("--metrics-url"), "--metrics-url", "nowhere"), sb8200test.Password, cli.ExitUsage, "no scheme or no host"},
		"an unknown flag":      {append(args, "--arris.password", "x"), sb8200test.Password, cli.ExitUsage, "flag provided but not defined"},
		"no modem address":     {without("--arris.url"), sb8200test.Password, cli.ExitError, "arris: --arris.url is empty"},
		"no fingerprint":       {without("--arris.fingerprint"), sb8200test.Password, cli.ExitError, "arris: --arris.fingerprint is empty"},
		"no password":          {args, "", cli.ExitError, "arris: ARRIS_PASSWORD is empty"},
		"an interval of zero":  {append(without("--arris.interval"), "--arris.interval", "0s"), sb8200test.Password, cli.ExitError, "arris: --arris.interval is not above zero"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("ARRIS_PASSWORD", test.password)

			code, stderr := start(t, test.args...).wait(t)
			if code != test.code || !strings.Contains(stderr, test.says) {
				t.Errorf("exit = %d, want %d and %q:\n%s", code, test.code, test.says, stderr)
			}
		})
	}

	select {
	case got := <-st.writes:
		t.Errorf("a refused configuration wrote to the store: %q", got.body)
	default:
	}
}

// listening is a UDP address nothing listens on, for the collector to take.
func listening(t *testing.T) string {
	t.Helper()

	var config net.ListenConfig

	conn, err := config.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	address := conn.LocalAddr().String()

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	return address
}

// send sends datagram to address until the store has a write, since
// nothing says when the collector has begun to listen, and returns it.
func send(t *testing.T, st *store, address, datagram string) write {
	t.Helper()

	var dialer net.Dialer

	conn, err := dialer.DialContext(t.Context(), "udp", address)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = conn.Close() }()

	for deadline := time.Now().Add(patience); time.Now().Before(deadline); {
		// A refusal is the port not open yet; the next try finds it.
		_, _ = conn.Write([]byte(datagram))

		select {
		case got := <-st.writes:
			return got
		case <-time.After(50 * time.Millisecond):
		}
	}

	t.Fatal("no line reached the logs store")

	return write{}
}

func TestUniFiSyslogReachesTheLogsStore(t *testing.T) {
	t.Parallel()

	st := newStore(t, 0)
	address := listening(t)

	col := start(t,
		"--enable", "unifi-syslog",
		"--logs-url", st.server.URL,
		"--unifi-syslog.listen", address,
		"--unifi-syslog.location", "America/Los_Angeles",
	)

	got := send(t, st, address, "<14>Nov 15 15:54:49 Gateway Gateway mcad[4588]: the text\n")

	if code, stderr := col.stop(t); code != cli.ExitOK {
		t.Fatalf("exit = %d:\n%s", code, stderr)
	}

	query, err := url.ParseQuery(got.query)
	if err != nil {
		t.Fatal(err)
	}

	if got.path != "/insert/jsonline" || query.Get("_stream_fields") != "job,host.name,service.name" ||
		query.Get("_msg_field") != "_msg" || query.Get("_time_field") != "_time" {
		t.Errorf("the write went to %q with %q", got.path, got.query)
	}

	var line map[string]string

	if err = json.Unmarshal([]byte(strings.SplitN(got.body, "\n", 2)[0]), &line); err != nil {
		t.Fatalf("the logs store was sent %q: %v", got.body, err)
	}

	for name, want := range map[string]string{
		"_msg":                 "the text",
		"job":                  "unifi-syslog",
		"host.name":            "Gateway",
		"service.name":         "mcad",
		"process.pid":          "4588",
		"severity_text":        "info",
		"syslog.facility":      "user",
		"network.peer.address": "127.0.0.1",
	} {
		if line[name] != want {
			t.Errorf("%s is %q, want %q, in %q", name, line[name], want, got.body)
		}
	}

	// The year is this one's: the line has none.
	at, err := time.Parse(time.RFC3339Nano, line["_time"])
	if err != nil || at.Month() != time.November || at.Day() != 15 || at.Hour() != 23 || at.Minute() != 54 {
		t.Errorf("_time is %q: %v", line["_time"], err)
	}
}

func TestALineTheStoreRefusesIsLost(t *testing.T) {
	t.Parallel()

	st := newStore(t, 1)
	address := listening(t)

	col := start(t,
		"--enable", "unifi-syslog",
		"--logs-url", st.server.URL,
		"--unifi-syslog.listen", address,
	)

	// The first line the store sees is refused; the collector goes on to
	// the next and does not send the first again.
	first := send(t, st, address, "<14>Nov 15 15:54:49 Gateway Gateway mcad[1]: one\n")
	second := send(t, st, address, "<14>Nov 15 15:54:50 Gateway Gateway mcad[1]: two\n")

	if !strings.Contains(first.body, `"_msg":"one"`) || !strings.Contains(second.body, `"_msg":"`) {
		t.Errorf("the store was sent %q then %q", first.body, second.body)
	}

	if code, stderr := col.stop(t); code != cli.ExitOK {
		t.Fatalf("exit = %d:\n%s", code, stderr)
	}
}

func TestWhatADeploymentGetsWrongForSyslog(t *testing.T) {
	t.Parallel()

	st := newStore(t, 0)

	for name, test := range map[string]struct {
		args []string
		says string
	}{
		"no logs store": {
			[]string{"--enable", "unifi-syslog", "--unifi-syslog.listen", "127.0.0.1:0"},
			"unifi-syslog: it writes logs and --logs-url is empty",
		},
		"no address": {
			[]string{"--enable", "unifi-syslog", "--logs-url", st.server.URL},
			"unifi-syslog: --unifi-syslog.listen is empty",
		},
		"a time zone that is none": {
			[]string{
				"--enable", "unifi-syslog", "--logs-url", st.server.URL,
				"--unifi-syslog.listen", "127.0.0.1:0", "--unifi-syslog.location", "Mars/Olympus",
			},
			"unifi-syslog: --unifi-syslog.location:",
		},
		"an address that is none": {
			[]string{"--enable", "unifi-syslog", "--logs-url", st.server.URL, "--unifi-syslog.listen", "nowhere"},
			"unifi-syslog: --unifi-syslog.listen:",
		},
	} {
		code, stderr := start(t, test.args...).wait(t)
		if code != cli.ExitError || !strings.Contains(stderr, test.says) {
			t.Errorf("%s: exit = %d, want %d and %q:\n%s", name, code, cli.ExitError, test.says, stderr)
		}
	}
}

// unifiConsole is a console holding the devices of testdata, and the
// arguments that point the collector at it.
func unifiConsole(t *testing.T, st *store) []string {
	t.Helper()

	data, err := xos.ReadFile(filepath.Join("testdata", "unifi-devices.json"))
	if err != nil {
		t.Fatal(err)
	}

	var devices []map[string]any
	if err := json.Unmarshal(data, &devices); err != nil {
		t.Fatal(err)
	}

	fake := consoletest.New(map[string][]map[string]any{"device": devices})
	t.Cleanup(fake.Close)

	pin := sha256.Sum256(fake.Certificate().Raw)

	return []string{
		"--enable", "unifi",
		"--metrics-url", st.server.URL,
		"--unifi.url", fake.URL,
		"--unifi.fingerprint", hex.EncodeToString(pin[:]),
		"--unifi.interval", "1h",
	}
}

func TestTheConsolesDevicesReachTheMetricsStore(t *testing.T) {
	t.Setenv("UNIFI_API_KEY", consoletest.APIKey)

	st := newStore(t, 0)

	col := start(t, unifiConsole(t, st)...)
	got := st.next(t)

	if code, stderr := col.stop(t); code != cli.ExitOK {
		t.Fatalf("exit = %d:\n%s", code, stderr)
	}

	golden := filepath.Join("testdata", "unifi.golden")
	sent := untimed(t, got.body)

	if *update {
		if err := xos.WriteFile(golden, []byte(sent), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	want, err := xos.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}

	if sent != string(want) {
		t.Errorf("the metrics store was sent:\n%s\nwant, from %s:\n%s", sent, golden, want)
	}
}

func TestAConsoleThatRefusesIsWrittenAsDown(t *testing.T) {
	t.Setenv("UNIFI_API_KEY", "not the key")

	st := newStore(t, 0)

	col := start(t, unifiConsole(t, st)...)

	if got := untimed(t, st.next(t).body); got != "unifi_up{job=\"unifi\"} 0\n" {
		t.Errorf("the metrics store was sent:\n%s", got)
	}

	// The collector goes on: a console that refuses is not a reason to stop.
	select {
	case code := <-col.done:
		t.Fatalf("the collector ended, exit %d:\n%s", code, col.stderr.String())
	default:
	}

	if code, stderr := col.stop(t); code != cli.ExitOK {
		t.Fatalf("exit = %d:\n%s", code, stderr)
	}
}

func TestACertificateThatIsNotThePinnedOneIsWrittenAsDown(t *testing.T) {
	t.Setenv("UNIFI_API_KEY", consoletest.APIKey)

	st := newStore(t, 0)
	args := unifiConsole(t, st)

	for index, arg := range args {
		if arg == "--unifi.fingerprint" {
			args[index+1] = strings.Repeat("00", sha256.Size)
		}
	}

	col := start(t, args...)

	if got := untimed(t, st.next(t).body); got != "unifi_up{job=\"unifi\"} 0\n" {
		t.Errorf("the metrics store was sent:\n%s", got)
	}

	if code, stderr := col.stop(t); code != cli.ExitOK {
		t.Fatalf("exit = %d:\n%s", code, stderr)
	}
}

func TestWhatADeploymentGetsWrongForTheConsole(t *testing.T) {
	t.Setenv("UNIFI_API_KEY", consoletest.APIKey)

	st := newStore(t, 0)
	whole := unifiConsole(t, st)

	// A console answering in the clear: asked anything, the key has left.
	asked := make(chan string, 1)
	plain := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case asked <- r.Header.Get("X-Api-Key"):
		default:
		}
	}))
	t.Cleanup(plain.Close)

	// without is the whole command line less one flag and its value.
	without := func(dropped string) []string {
		var args []string

		for index := 0; index < len(whole); index += 2 {
			if whole[index] != dropped {
				args = append(args, whole[index], whole[index+1])
			}
		}

		return args
	}

	for name, test := range map[string]struct {
		key  string
		args []string
		says string
	}{
		"no metrics store": {consoletest.APIKey, without("--metrics-url"), "unifi: it writes metrics and --metrics-url is empty"},
		"no address":       {consoletest.APIKey, without("--unifi.url"), "unifi: --unifi.url is empty"},
		"an address in the clear": {
			consoletest.APIKey, append(without("--unifi.url"), "--unifi.url", plain.URL),
			"unifi: --unifi.url is not an https address",
		},
		"an address with no scheme": {
			consoletest.APIKey, append(without("--unifi.url"), "--unifi.url", "console.example"),
			"unifi: --unifi.url is not an https address",
		},
		"no fingerprint": {consoletest.APIKey, without("--unifi.fingerprint"), "unifi: --unifi.fingerprint is empty"},
		"no key":         {"", whole, "unifi: UNIFI_API_KEY is empty"},
		"no interval": {
			consoletest.APIKey, append(without("--unifi.interval"), "--unifi.interval", "0s"),
			"unifi: --unifi.interval is not above zero",
		},
		"a fingerprint that is none": {
			consoletest.APIKey, append(without("--unifi.fingerprint"), "--unifi.fingerprint", "zz"),
			"unifi: --unifi.fingerprint:",
		},
	} {
		t.Setenv("UNIFI_API_KEY", test.key)

		code, stderr := start(t, test.args...).wait(t)
		if code != cli.ExitError || !strings.Contains(stderr, test.says) {
			t.Errorf("%s: exit = %d, want %d and %q:\n%s", name, code, cli.ExitError, test.says, stderr)
		}
	}

	select {
	case got := <-st.writes:
		t.Errorf("a deployment that was refused wrote:\n%s", got.body)
	default:
	}

	select {
	case key := <-asked:
		t.Errorf("an address in the clear was sent a request, with the key %q", key)
	default:
	}
}
