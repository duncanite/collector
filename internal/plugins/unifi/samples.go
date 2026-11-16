package unifi

import (
	"encoding/json"
	"strconv"
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

// samples is the console's device list as series.
func samples(docs []console.Document, now time.Time) []plugin.Sample {
	all := &series{now: now}
	all.add("unifi_up", 1, nil)

	for _, doc := range docs {
		device(all, doc)
	}

	return all.out
}

// device is one device's document: the gateway, a switch or an access
// point. What only some of them have, radios, ports, an uplink to the
// internet, is written for those that do.
func device(all *series, doc map[string]any) {
	mac := text(doc["mac"])

	called := text(doc["name"])
	if called == "" {
		// A device nobody named is known by its address.
		called = mac
	}

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
		index, _ := number(port["port_idx"])

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

// number is the number in value. The console writes its numbers three
// ways, sometimes on one document: as a number, as a number in a string
// ("15.4"), and, read by a decoder that keeps them exact, as a
// json.Number.
func number(value any) (float64, bool) {
	switch held := value.(type) {
	case json.Number:
		parsed, err := held.Float64()

		return parsed, err == nil
	case float64:
		return held, true
	case string:
		parsed, err := strconv.ParseFloat(held, 64)

		return parsed, err == nil
	default:
		return 0, false
	}
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
