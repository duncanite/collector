package unifi_test

import (
	"bytes"
	"encoding/json"
	"net/netip"
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

	return reported(t, list, "[]", "[]")
}

// documents is a JSON list as the console's library hands one over.
func documents(t *testing.T, list string) []console.Document {
	t.Helper()

	var docs []console.Document

	decoder := json.NewDecoder(bytes.NewReader([]byte(list)))
	decoder.UseNumber()

	if err := decoder.Decode(&docs); err != nil {
		t.Fatal(err)
	}

	return docs
}

// reported is the series the console's three reports become, written as
// written does.
func reported(t *testing.T, devices, clients, health string) string {
	t.Helper()

	var out strings.Builder

	for _, sample := range unifi.Series(
		documents(t, devices), documents(t, clients), documents(t, health), time.Unix(0, 0),
	) {
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

func TestAClientIsCalledByItsNameItsHostNameOrItsAddress(t *testing.T) {
	t.Parallel()

	got := reported(t, "[]", `[
		{"mac": "a", "name": "Laptop", "hostname": "laptop-host", "uptime": 1},
		{"mac": "b", "hostname": "thermostat", "uptime": 2},
		{"mac": "c", "uptime": 3},
		{"mac": "d", "name": "Twin", "uptime": 4},
		{"mac": "e", "hostname": "Twin", "uptime": 5}
	]`, "[]")

	holds(t, got,
		"unifi_client_uptime_seconds{client=Laptop} 1",
		"unifi_client_uptime_seconds{client=thermostat} 2",
		"unifi_client_uptime_seconds{client=c} 3",
		// One named Twin and one that calls itself Twin: each by its address.
		"unifi_client_uptime_seconds{client=d} 4",
		"unifi_client_uptime_seconds{client=e} 5",
	)
	lacks(t, got, "client=Twin", "client=laptop-host")
}

func TestAWirelessClientAndAWiredOneAreNotMeasuredAlike(t *testing.T) {
	t.Parallel()

	got := reported(t, "[]", `[
		{"mac": "a", "name": "Phone", "is_wired": false, "network": "Family", "last_uplink_name": "Attic",
		 "essid": "Home", "radio": "na", "signal": -52, "noise": -98, "rx_rate": 866000, "tx_rate": 780000,
		 "wifi_tx_retries_percentage": 2.5, "rx_bytes": 300, "tx_bytes": 4100,
		 "wired_rate_mbps": 1000, "wired-rx_bytes": 9, "wired-tx_bytes": 9},
		{"mac": "b", "name": "Desk", "is_wired": true, "network": "Family", "last_uplink_name": "Switch",
		 "wired_rate_mbps": 1000, "wired-rx_bytes": 520, "wired-tx_bytes": 9100,
		 "signal": -1, "rx_rate": 1, "wifi_tx_retries_percentage": 0, "rx_bytes": 9, "tx_bytes": 9},
		{"mac": "c", "name": "Unsaid", "signal": -60}
	]`, "[]")

	holds(t, got,
		"unifi_client_info{client=Phone,mac=a,wired=false,essid=Home,network=Family,radio=na,uplink=Attic} 1",
		"unifi_client_signal_dbm{client=Phone} -52",
		"unifi_client_noise_dbm{client=Phone} -98",
		"unifi_client_receive_rate_kbps{client=Phone} 866000",
		"unifi_client_retries_percent{client=Phone} 2.5",
		"unifi_client_receive_bytes_total{client=Phone} 300",
		"unifi_client_transmit_bytes_total{client=Phone} 4100",
		// What the console does not say of a client is not a label.
		"unifi_client_info{client=Desk,mac=b,wired=true,network=Family,uplink=Switch} 1",
		"unifi_client_link_mbps{client=Desk} 1000",
		"unifi_client_receive_bytes_total{client=Desk} 520",
		"unifi_client_transmit_bytes_total{client=Desk} 9100",
		// A client that does not say is wireless, as the console leaves it.
		"unifi_client_info{client=Unsaid,mac=c,wired=false} 1",
		"unifi_client_signal_dbm{client=Unsaid} -60",
	)
	lacks(t, got,
		"unifi_client_link_mbps{client=Phone}",
		"unifi_client_signal_dbm{client=Desk}", "unifi_client_receive_rate_kbps{client=Desk}",
		"unifi_client_retries_percent{client=Desk}",
	)
}

func TestASubsystemsVerdict(t *testing.T) {
	t.Parallel()

	got := reported(t, "[]", "[]", `[
		{"subsystem": "wlan", "status": "ok", "num_user": 2, "num_guest": 0, "num_adopted": 1},
		{"subsystem": "wan", "status": "error", "num_sta": 3, "num_disconnected": 1},
		{"subsystem": "www", "status": "warning", "latency": 14, "drops": 2, "uptime": 90000},
		{"subsystem": "vpn", "status": "unknown"},
		{"subsystem": "lan"}
	]`)

	holds(t, got,
		"unifi_health_ok{subsystem=wlan} 1",
		"unifi_health_users{subsystem=wlan} 2",
		"unifi_health_guests{subsystem=wlan} 0",
		"unifi_health_adopted{subsystem=wlan} 1",
		// Anything said that is not "ok" is not ok.
		"unifi_health_ok{subsystem=wan} 0",
		"unifi_health_clients{subsystem=wan} 3",
		"unifi_health_disconnected{subsystem=wan} 1",
		"unifi_health_ok{subsystem=www} 0",
		"unifi_health_latency_milliseconds{subsystem=www} 14",
		"unifi_health_drops{subsystem=www} 2",
		"unifi_health_uptime_seconds{subsystem=www} 90000",
	)
	// A subsystem the house does not have, and one with no verdict, have none.
	lacks(t, got, "subsystem=vpn", "subsystem=lan")
}

// TestAnAddressIsCalledWhatItsSeriesAre gives the console's devices and
// clients addresses: each is told under the name its series carry, and an
// address that is none, or that two of them hold, is told of nobody.
func TestAnAddressIsCalledWhatItsSeriesAre(t *testing.T) {
	t.Parallel()

	got := unifi.Addresses(
		documents(t, `[
			{"mac": "01", "name": "Gateway", "ip": "192.0.2.1"},
			{"mac": "02", "name": "Attic", "ip": "192.0.2.2"}
		]`),
		documents(t, `[
			{"mac": "a", "name": "Laptop", "hostname": "laptop-host", "ip": "192.0.2.7"},
			{"mac": "b", "hostname": "thermostat", "ip": "::ffff:192.0.2.8"},
			{"mac": "c", "ip": "2001:db8::9"},
			{"mac": "d", "name": "Unaddressed"},
			{"mac": "e", "name": "Nowhere", "ip": "0.0.0.0"},
			{"mac": "f", "name": "Garbled", "ip": "192.0.2"},
			{"mac": "g", "name": "Numbered", "ip": 7},
			{"mac": "h", "name": "Was here", "ip": "192.0.2.20"},
			{"mac": "i", "name": "Is here", "ip": "192.0.2.20"},
			{"mac": "j", "name": "On the attic's", "ip": "192.0.2.2"}
		]`),
	)

	want := map[string]string{
		"192.0.2.1":   "Gateway",
		"192.0.2.7":   "Laptop",
		"192.0.2.8":   "thermostat",
		"2001:db8::9": "c",
	}

	if len(got) != len(want) {
		t.Errorf("%d addresses are named, want %d: %v", len(got), len(want), got)
	}

	for address, name := range want {
		if got[netip.MustParseAddr(address)] != name {
			t.Errorf("%s is %q, want %q", address, got[netip.MustParseAddr(address)], name)
		}
	}
}
