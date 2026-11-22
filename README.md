# collector

The Duncanite house's one door for telemetry: a small program that listens to, or goes and
asks, each source of logs and metrics in the house, and hands what it gets to the stores.
The stores behind it are not this repository's.

It is deliberately not clever. Nothing is batched, queued or tried again: what a source
gives is sent to the store at once, and a write the store refuses is logged and lost. The
data is low in volume and mostly disposable, and a client that pushes to the collector
handles its own back-pressure.

## Plugins

Every source is a plugin, a Go package under `internal/plugins` that implements
`plugin.Plugin` (`internal/plugin`): a name, its own flags, and a `Run` that collects until
it is told to stop. All plugins are compiled into the one binary, listed in
`cmd/collector/main.go`; a deployment chooses the ones that run with `--enable`, and gives
each its settings through that plugin's flags. Nothing here names a host or an address.

| Plugin | Source | Writes |
|--------|--------|--------|
| `arris` | An Arris SURFboard cable modem, read every `--arris.interval` over [go-arris](https://github.com/duncanite/go-arris) | Metrics: `arris_up`, the uptime, and per bonded channel its lock, frequency, power, signal-to-noise ratio and codeword error counts |
| `ipfix` | IPFIX, the flow export a gateway calls NetFlow version 10, received on UDP at `--ipfix.listen` | Logs: one record a flow, its text the flow in a line (`tcp 192.0.2.7:51000 > 198.51.100.9:443 5344385 bytes 5009 packets`), with its addresses, ports and protocol under the names a firewall line has them, every other element under IANA's name as `ipfix.<name>`, and the exporter's address |
| `otlp` | The house's own programs that speak OpenTelemetry, sending OTLP over HTTP to `--otlp.listen` | Whatever they send, unread: `/v1/metrics` to the metrics store and `/v1/logs` to the logs store, and the store's answer back to the sender |
| `unifi` | A UniFi Network console, asked every `--unifi.interval` over [go-unifi](https://github.com/duncanite/go-unifi) for its devices, its clients and its health | Metrics: `unifi_up`; per device whether the console is in touch with it, its uptime, processor, memory, temperature and clients; per radio of an access point its channel, clients, utilization and retries; per port its link, speed, traffic, errors and power; per uplink to the internet its latency and availability; per client where it is attached, its signal, rate, retries and traffic, or its link's speed when wired; per subsystem of the console its verdict and its counts |
| `unifi-syslog` | UniFi's remote syslog, received on UDP at `--unifi-syslog.listen`: the gateway, the access points, the switch, and the console's CEF events | Logs: one record a line, with the host, the program and its pid, an access point's model and firmware, a firewall line's rule, policy, addresses and ports, a console event's fields under `cef.*`, and the sender's address |

```bash
ARRIS_PASSWORD=… collector \
    --enable arris \
    --metrics-url http://<victoriametrics>:8428 \
    --arris.host <modem> \
    --arris.fingerprint <sha-256 of the modem's certificate, hex>
```

A credential comes from the environment, never from a flag. A plugin that is enabled and
misconfigured stops the collector at its start; a source that does not answer does not: the
`arris` plugin writes `arris_up 0` for that read and tries again at the next interval.

Metrics go to VictoriaMetrics' import API in the Prometheus text format, one request per
read, each sample labelled with its plugin's name as `job`. Logs go to VictoriaLogs' JSON
lines API, one request per line or per datagram of flows, under OpenTelemetry's names
where it has one (`host.name`, `service.name`, `process.pid`), in the streams each plugin
names. While a store is down, everything meant for it in that time is lost; a deployment
names the stores its plugins need with `--metrics-url` and `--logs-url`, and a plugin
whose store is not named refuses to run.

`unifi-syslog` takes lines over plain UDP, with nothing to say who sent them: whoever
reaches its port writes into the logs store. What a line can make of its record is
bounded, and what is not is said here:

- The sender's address is kept on every record, and is the one thing the store groups
  the plugin's lines by: a line names its own host and program, so those are fields and
  never a stream.
- A record is dated by its line when the line says it happened within a day of its
  reading, and by its reading otherwise. The same holds for a console event's own time.
- A console event gives as many fields as the console writes, sixty-four at most; one
  with more keeps its text whole. Every other line gives a fixed handful.
- What is not UTF-8, and every control character but the tab and the line feed, is
  replaced.
- A line of a shape nobody mapped is stored with its text whole.

Not bounded: who sends (https://github.com/duncanite/collector/issues/13), how many lines,
and what they say. A host name, a program, a firewall policy and every value are the
line's own word.

Its parser is fuzzed (`FuzzParse`), and its fixtures,
`internal/plugins/unifisyslog/testdata`, hold one line per shape a device sends, every name
and address in them a placeholder.

`ipfix` takes messages the same way, over plain UDP from whoever reaches its port, and
reads IPFIX only (RFC 7011): NetFlow 5 and 9 are refused. An exporter says how its records
are laid out in templates it sends again every so many datagrams, so the flows that come
before the first of them are not read. What a message can make of the collector and of
the store is bounded:

- 256 templates are held, over every exporter; one more puts out the one defined longest
  ago, which its exporter defines again at its next refresh. A template has 128 fields at
  most, and is its exporter's own: its address, its port and its observation domain.
- A datagram gives 512 flows at most, each with its template's fields and three more: the
  exporter's address, which is the one thing the store groups the plugin's records by, the
  observation domain and the template's number.
- A flow is dated by its own end when that is within a day of its reading, else by when
  the exporter saw it or sent it, under the same condition, else by its reading.
- An element of IANA's this build has no name for, and an enterprise's own, is written in
  hex under its number, `ipfix.<element>` or `ipfix.<enterprise>.<element>`, sixty-four
  octets of it at most; a string is cut at 256 octets and cleaned as a syslog line is.
  The records of an options template, what the exporter says of itself, are skipped.
- A datagram that is not read whole is counted, and said in the collector's own log at
  most once a minute.

Not bounded, as for syslog: who sends, how many flows, and what they say, a template
another sender defines under an exporter's address and port among it.

Its reader is fuzzed (`FuzzRead`) and reads the worked example of the RFC's appendix A. It
has not met a gateway's export yet: every message in its tests is written by hand from the
RFC.

`otlp` reads nothing of what it passes on, keeps nothing and tries nothing again: a request
the store refuses is answered with the store's own refusal, and a store that is gone with a
502, for the sender's exporter to do what it does. A request is streamed and never held; one
larger than 16 MiB is refused. It asks no credential: whoever reaches its port writes into
the stores.

## Working on it

```bash
just lint       # the shared limen baseline and the Go lane
just test       # the plugins against a stand-in modem and stand-in stores
just security   # the shared scans, the link check and the Go vulnerability scan
just fix        # repair what `just lint` reports
```

`just --list` shows the rest.
