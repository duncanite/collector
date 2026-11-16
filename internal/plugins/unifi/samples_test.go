package unifi_test

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/duncanite/go-unifi/console"

	"github.com/duncanite/collector/internal/plugins/unifi"
)

// written is the series a device list becomes, one a line as
// "name{label=value,…} value", the way the console's library would hand
// the list over: numbers kept as json.Number.
func written(t *testing.T, list string) string {
	t.Helper()

	var docs []console.Document

	decoder := json.NewDecoder(bytes.NewReader([]byte(list)))
	decoder.UseNumber()

	if err := decoder.Decode(&docs); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder

	for _, sample := range unifi.Samples(docs, time.Unix(0, 0)) {
		out.WriteString(sample.Name)
		out.WriteByte('{')

		for index, label := range sample.Labels {
			if index > 0 {
				out.WriteByte(',')
			}

			out.WriteString(label.Name + "=" + label.Value)
		}

		out.WriteString("} ")
		out.WriteString(strconv.FormatFloat(sample.Value, 'f', -1, 64))
		out.WriteByte('\n')
	}

	return out.String()
}

func holds(t *testing.T, got string, lines ...string) {
	t.Helper()

	for _, line := range lines {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("no line %q in:\n%s", line, got)
		}
	}
}

func lacks(t *testing.T, got string, fragments ...string) {
	t.Helper()

	for _, fragment := range fragments {
		if strings.Contains(got, fragment) {
			t.Errorf("%q is in:\n%s", fragment, got)
		}
	}
}

func TestADeviceIsCalledByItsNameUnlessThatTellsNothing(t *testing.T) {
	t.Parallel()

	got := written(t, `[
		{"mac": "00:00:5e:00:53:01", "name": "Attic", "uptime": 1},
		{"mac": "00:00:5e:00:53:02", "uptime": 2},
		{"mac": "00:00:5e:00:53:03", "name": "Twin", "uptime": 3, "state": 1},
		{"mac": "00:00:5e:00:53:04", "name": "Twin", "uptime": 4, "state": 0}
	]`)

	holds(t, got,
		"unifi_device_uptime_seconds{device=Attic} 1",
		// Nobody named it.
		"unifi_device_uptime_seconds{device=00:00:5e:00:53:02} 2",
		// Two of one name: each by its address, so no series is written twice.
		"unifi_device_uptime_seconds{device=00:00:5e:00:53:03} 3",
		"unifi_device_uptime_seconds{device=00:00:5e:00:53:04} 4",
		"unifi_device_connected{device=00:00:5e:00:53:03} 1",
		"unifi_device_connected{device=00:00:5e:00:53:04} 0",
	)
	lacks(t, got, "device=Twin")
}

func TestOnlyStateOneIsConnected(t *testing.T) {
	t.Parallel()

	got := written(t, `[
		{"mac": "a", "name": "In touch", "state": 1},
		{"mac": "b", "name": "Gone", "state": 0},
		{"mac": "c", "name": "Adopting", "state": 7},
		{"mac": "d", "name": "Unsaid"}
	]`)

	holds(t, got,
		"unifi_device_connected{device=In touch} 1",
		"unifi_device_connected{device=Gone} 0",
		"unifi_device_connected{device=Adopting} 0",
	)
	lacks(t, got, "unifi_device_connected{device=Unsaid}")
}

func TestWhatIsNoNumberWritesNoSeries(t *testing.T) {
	t.Parallel()

	got := written(t, `[{
		"mac": "a", "name": "Odd",
		"uptime": "NaN", "num_sta": "Inf", "guest-num_sta": "-Inf",
		"rx_bytes": "0x10", "tx_bytes": " 5", "satisfaction": true, "total_used_power": null,
		"system-stats": {"cpu": "15.4", "mem": ""},
		"sys_stats": "not an object",
		"temperatures": [7, {"name": "CPU", "value": 41.5}],
		"port_table": [
			{"name": "No index", "up": true},
			{"port_idx": 2, "name": "Port 2", "up": true, "speed": "fast", "port_poe": false, "poe_power": "4.95"},
			{"port_idx": 3, "name": "Port 3", "up": "yes", "port_poe": true, "poe_power": "4.95"}
		]
	}]`)

	holds(t, got,
		"unifi_device_cpu_percent{device=Odd} 15.4",
		"unifi_device_temperature_celsius{device=Odd,sensor=CPU} 41.5",
		"unifi_port_up{device=Odd,port=2,port_name=Port 2} 1",
		"unifi_port_poe_watts{device=Odd,port=3,port_name=Port 3} 4.95",
	)
	lacks(t, got,
		"NaN", "Inf",
		"unifi_device_uptime_seconds", "unifi_device_clients", "unifi_device_guests",
		"unifi_device_receive_bytes_total", "unifi_device_transmit_bytes_total",
		"unifi_device_satisfaction_percent", "unifi_device_poe_watts",
		"unifi_device_memory_percent", "unifi_device_load1",
		// A port with no index has nothing to be told from the others by.
		"No index", "port=0",
		"unifi_port_speed_mbps",
		// The power of a port that feeds nothing, and a link that is no boolean.
		"unifi_port_poe_watts{device=Odd,port=2",
		"unifi_port_up{device=Odd,port=3",
	)
}

func TestBothUplinksAreWritten(t *testing.T) {
	t.Parallel()

	got := written(t, `[{
		"mac": "a", "name": "Gateway",
		"wan1": {"up": true, "latency": 10, "availability": 100},
		"wan2": {"up": false, "latency": 48, "availability": 62.5},
		"wan3": {"up": true}
	}]`)

	holds(t, got,
		"unifi_wan_up{device=Gateway,wan=wan1} 1",
		"unifi_wan_latency_milliseconds{device=Gateway,wan=wan1} 10",
		"unifi_wan_up{device=Gateway,wan=wan2} 0",
		"unifi_wan_latency_milliseconds{device=Gateway,wan=wan2} 48",
		"unifi_wan_availability_percent{device=Gateway,wan=wan2} 62.5",
	)
	lacks(t, got, "wan3")
}
