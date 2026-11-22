package unifi

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/duncanite/go-unifi/console"

	"github.com/duncanite/collector/internal/plugin"
)

// connected is the state the console gives a device it is in touch with.
const connected = 1

// The console's uplinks to the internet, by the key each is under on the
// gateway's document.
//
//nolint:gochecknoglobals // the two keys
var wans = [...]string{"wan1", "wan2"}

// series is the samples of one read, all at its time.
type series struct {
	now time.Time
	out []plugin.Sample
}

func (s *series) add(metric string, value float64, labels []plugin.Label) {
	s.out = append(s.out, plugin.Sample{Name: metric, Labels: labels, Value: value, Time: s.now})
}

// from adds metric with the number doc holds under key. A key that is not
// there, or holds no number, adds nothing: the console's documents differ
// by device and by release, and a series is not written from a guess.
func (s *series) from(metric string, doc map[string]any, key string, labels []plugin.Label) {
	if value, ok := number(doc[key]); ok {
		s.add(metric, value, labels)
	}
}

// flag adds metric as 1 or 0 from the boolean doc holds under key.
func (s *series) flag(metric string, doc map[string]any, key string, labels []plugin.Label) {
	if set, ok := doc[key].(bool); ok {
		s.add(metric, flag01(set), labels)
	}
}

// samples is one reading of the console as series.
func samples(read reading, now time.Time) []plugin.Sample {
	all := &series{now: now}
	all.add("unifi_up", 1, nil)

	for index, called := range names(read.devices, "name") {
		device(all, read.devices[index], called, text(read.devices[index]["mac"]))
	}

	// A client is called what its owner called it, or what it calls
	// itself.
	for index, called := range names(read.clients, "name", "hostname") {
		station(all, read.clients[index], called, text(read.clients[index]["mac"]))
	}

	for _, doc := range read.health {
		subsystem(all, doc)
	}

	return all.out
}

// names is what each document is called: the first of keys it holds, or
// its MAC when it holds none, or when another is called the same. A
// console keeps no two names apart, and two documents of one name would
// be one series written twice.
//
// A name is its owner's word or the host's own, and is a label a
// dashboard draws: it is made fit to be shown first, and two that come
// out the same are told apart by their MAC like any two.
func names(docs []console.Document, keys ...string) []string {
	called := make([]string, len(docs))
	count := make(map[string]int, len(docs))

	for index, doc := range docs {
		for _, key := range keys {
			if called[index] = plugin.Name(text(doc[key])); called[index] != "" {
				break
			}
		}

		count[called[index]]++
	}

	for index, doc := range docs {
		if called[index] == "" || count[called[index]] > 1 {
			called[index] = plugin.Name(text(doc["mac"]))
		}
	}

	return called
}

// station is one client's document. A wireless client has a signal and a
// rate; a wired one has its link's speed, and its traffic under keys of
// its own. The bytes are the console's count, from where it stands:
// received is what the client sent.
func station(all *series, doc map[string]any, called, mac string) {
	labels := []plugin.Label{{Name: "client", Value: called}}
	// A client that does not say is wireless, as the console leaves it.
	wired := truth(doc["is_wired"])

	// Where it is attached: the network, the device it hangs off, and for
	// a wireless one the name of the WiFi and the radio. What the console
	// does not say is left off.
	about := []plugin.Label{
		{Name: "client", Value: called},
		{Name: "mac", Value: mac},
		{Name: "wired", Value: strconv.FormatBool(wired)},
	}

	for label, key := range map[string]string{
		"network": "network", "uplink": "last_uplink_name", "essid": "essid", "radio": "radio",
	} {
		if value := text(doc[key]); value != "" {
			about = append(about, plugin.Label{Name: label, Value: value})
		}
	}

	slices.SortStableFunc(about[3:], func(a, b plugin.Label) int { return strings.Compare(a.Name, b.Name) })
	all.add("unifi_client_info", 1, about)

	all.from("unifi_client_uptime_seconds", doc, "uptime", labels)
	all.from("unifi_client_satisfaction_percent", doc, "satisfaction", labels)

	if wired {
		all.from("unifi_client_link_mbps", doc, "wired_rate_mbps", labels)
		all.from("unifi_client_receive_bytes_total", doc, "wired-rx_bytes", labels)
		all.from("unifi_client_transmit_bytes_total", doc, "wired-tx_bytes", labels)

		return
	}

	all.from("unifi_client_signal_dbm", doc, "signal", labels)
	all.from("unifi_client_noise_dbm", doc, "noise", labels)
	all.from("unifi_client_receive_rate_kbps", doc, "rx_rate", labels)
	all.from("unifi_client_transmit_rate_kbps", doc, "tx_rate", labels)
	all.from("unifi_client_retries_percent", doc, "wifi_tx_retries_percentage", labels)
	all.from("unifi_client_receive_bytes_total", doc, "rx_bytes", labels)
	all.from("unifi_client_transmit_bytes_total", doc, "tx_bytes", labels)
}

// subsystem is the console's verdict on one of its subsystems: the uplink
// (wan), the internet behind it (www), the wireless and the wired networks
// (wlan, lan), the VPN. Each holds the counts and measures that mean
// something for it, and none of the others'.
func subsystem(all *series, doc map[string]any) {
	labels := []plugin.Label{{Name: "subsystem", Value: text(doc["subsystem"])}}

	// "unknown" is a subsystem the house does not have: no verdict, and
	// not a bad one.
	if status := text(doc["status"]); status != "" && status != "unknown" {
		all.add("unifi_health_ok", flag01(status == "ok"), labels)
	}

	all.from("unifi_health_clients", doc, "num_sta", labels)
	all.from("unifi_health_users", doc, "num_user", labels)
	all.from("unifi_health_guests", doc, "num_guest", labels)
	all.from("unifi_health_adopted", doc, "num_adopted", labels)
	all.from("unifi_health_disconnected", doc, "num_disconnected", labels)
	all.from("unifi_health_pending", doc, "num_pending", labels)
	all.from("unifi_health_latency_milliseconds", doc, "latency", labels)
	all.from("unifi_health_drops", doc, "drops", labels)
	all.from("unifi_health_uptime_seconds", doc, "uptime", labels)
}

// device is one device's document: the gateway, a switch or an access
// point. What only some of them have, radios, ports, an uplink to the
// internet, is written for those that do.
func device(all *series, doc map[string]any, called, mac string) {
	labels := []plugin.Label{{Name: "device", Value: called}}

	all.add("unifi_device_info", 1, []plugin.Label{
		{Name: "device", Value: called},
		{Name: "mac", Value: mac},
		{Name: "type", Value: text(doc["type"])},
		{Name: "model", Value: text(doc["model"])},
		{Name: "version", Value: text(doc["version"])},
	})

	if state, ok := number(doc["state"]); ok {
		all.add("unifi_device_connected", flag01(state == connected), labels)
	}

	all.from("unifi_device_uptime_seconds", doc, "uptime", labels)
	all.from("unifi_device_clients", doc, "num_sta", labels)
	all.from("unifi_device_guests", doc, "guest-num_sta", labels)
	all.from("unifi_device_satisfaction_percent", doc, "satisfaction", labels)
	all.from("unifi_device_receive_bytes_total", doc, "rx_bytes", labels)
	all.from("unifi_device_transmit_bytes_total", doc, "tx_bytes", labels)
	all.flag("unifi_device_upgradable", doc, "upgradable", labels)
	all.from("unifi_device_poe_watts", doc, "total_used_power", labels)
	all.from("unifi_device_poe_budget_watts", doc, "total_max_power", labels)

	if stats := object(doc["system-stats"]); stats != nil {
		all.from("unifi_device_cpu_percent", stats, "cpu", labels)
		all.from("unifi_device_memory_percent", stats, "mem", labels)
	}

	if stats := object(doc["sys_stats"]); stats != nil {
		all.from("unifi_device_load1", stats, "loadavg_1", labels)
	}

	for _, sensor := range objects(doc["temperatures"]) {
		all.from("unifi_device_temperature_celsius", sensor, "value",
			with(labels, "sensor", text(sensor["name"])))
	}

	for _, radio := range objects(doc["radio_table_stats"]) {
		radios(all, radio, with(labels, "radio", text(radio["radio"])))
	}

	for _, port := range objects(doc["port_table"]) {
		index, numbered := number(port["port_idx"])
		if !numbered {
			// Nothing to tell it from the device's other ports by.
			continue
		}

		ports(all, port, with(
			with(labels, "port", strconv.FormatFloat(index, 'f', -1, 64)),
			"port_name", text(port["name"]),
		))
	}

	for _, key := range wans {
		if wan := object(doc[key]); wan != nil {
			uplink(all, wan, with(labels, "wan", key))
		}
	}
}

// radios is one radio of an access point: "ng" is 2.4 GHz, "na" 5 GHz,
// "6e" 6 GHz, as the console names them.
func radios(all *series, radio map[string]any, labels []plugin.Label) {
	all.from("unifi_radio_channel", radio, "channel", labels)
	all.from("unifi_radio_clients", radio, "num_sta", labels)
	all.from("unifi_radio_utilization_percent", radio, "cu_total", labels)
	all.from("unifi_radio_transmit_power_dbm", radio, "tx_power", labels)
	all.from("unifi_radio_retries_percent", radio, "tx_retries_pct", labels)
	all.from("unifi_radio_satisfaction_percent", radio, "satisfaction", labels)
}

// ports is one port of a switch or of the gateway.
func ports(all *series, port map[string]any, labels []plugin.Label) {
	all.flag("unifi_port_up", port, "up", labels)
	all.from("unifi_port_speed_mbps", port, "speed", labels)
	all.from("unifi_port_receive_bytes_total", port, "rx_bytes", labels)
	all.from("unifi_port_transmit_bytes_total", port, "tx_bytes", labels)
	all.from("unifi_port_receive_errors_total", port, "rx_errors", labels)
	all.from("unifi_port_transmit_errors_total", port, "tx_errors", labels)
	all.from("unifi_port_receive_dropped_total", port, "rx_dropped", labels)
	all.from("unifi_port_transmit_dropped_total", port, "tx_dropped", labels)

	// Every port carries the power fields; they mean something on a port
	// that can feed a device.
	if feeds, ok := port["port_poe"].(bool); ok && feeds {
		all.from("unifi_port_poe_watts", port, "poe_power", labels)
	}
}

// uplink is one of the gateway's links to the internet.
func uplink(all *series, wan map[string]any, labels []plugin.Label) {
	all.flag("unifi_wan_up", wan, "up", labels)
	all.from("unifi_wan_latency_milliseconds", wan, "latency", labels)
	all.from("unifi_wan_availability_percent", wan, "availability", labels)
	all.from("unifi_wan_speed_mbps", wan, "speed", labels)
	all.from("unifi_wan_receive_bytes_total", wan, "rx_bytes", labels)
	all.from("unifi_wan_transmit_bytes_total", wan, "tx_bytes", labels)
}

// with is labels and one more, in a slice of its own.
func with(labels []plugin.Label, name, value string) []plugin.Label {
	out := make([]plugin.Label, 0, len(labels)+1)
	out = append(out, labels...)

	return append(out, plugin.Label{Name: name, Value: value})
}

// number is the number in value. The console writes its numbers two
// ways, sometimes on one document: as a number, which go-unifi's decoder
// hands over as a json.Number, and as a number in a string ("15.4"). What
// is not a finite number is none: "NaN" and "Inf" parse, and are no
// measurement.
func number(value any) (float64, bool) {
	var (
		parsed float64
		err    error
	)

	switch held := value.(type) {
	case json.Number:
		parsed, err = held.Float64()
	case string:
		parsed, err = strconv.ParseFloat(held, 64)
	default:
		return 0, false
	}

	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, false
	}

	return parsed, true
}

// truth is the boolean in value, false when it holds none.
func truth(value any) bool {
	held, ok := value.(bool)

	return ok && held
}

// text is the string in value, or none.
func text(value any) string {
	if held, ok := value.(string); ok {
		return held
	}

	return ""
}

// object is the object in value, or nil.
func object(value any) map[string]any {
	if held, ok := value.(map[string]any); ok {
		return held
	}

	return nil
}

// objects is the objects of a list, whatever else it holds left out.
func objects(value any) []map[string]any {
	list, ok := value.([]any)
	if !ok {
		return nil
	}

	out := make([]map[string]any, 0, len(list))

	for _, item := range list {
		if held := object(item); held != nil {
			out = append(out, held)
		}
	}

	return out
}

func flag01(set bool) float64 {
	if set {
		return 1
	}

	return 0
}
