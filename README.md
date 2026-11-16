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
| `unifi` | A UniFi Network console, asked for its devices every `--unifi.interval` over [go-unifi](https://github.com/duncanite/go-unifi) | Metrics: `unifi_up`, and per device whether the console is in touch with it, its uptime, processor, memory, temperature and clients; per radio of an access point its channel, clients, utilization and retries; per port its link, speed, traffic, errors and power; per uplink to the internet its latency and availability |
| `unifi-syslog` | UniFi's remote syslog, received on UDP at `--unifi-syslog.listen`: the gateway, the access points, the switch, and the console's CEF events | Logs: one record a line, with the host, the program and its pid, an access point's model and firmware, a firewall line's rule, policy, addresses and ports, a console event's fields under `cef.*`, and the sender's address |

```bash
ARRIS_PASSWORD=… collector \
    --enable arris \
    --metrics-url http://<victoriametrics>:8428 \
    --arris.url https://<modem> \
    --arris.fingerprint <sha-256 of the modem's certificate, hex>
```

A credential comes from the environment, never from a flag. A plugin that is enabled and
misconfigured stops the collector at its start; a source that does not answer does not: the
`arris` plugin writes `arris_up 0` for that read and tries again at the next interval.

Metrics go to VictoriaMetrics' import API in the Prometheus text format, one request per
read, each sample labelled with its plugin's name as `job`. Logs go to VictoriaLogs' JSON
lines API, one request per line, under OpenTelemetry's names where it has one (`host.name`,
`service.name`, `process.pid`), in one stream per program per host per plugin. While a
store is down, everything meant for it in that time is lost; a deployment names the stores
its plugins need with `--metrics-url` and `--logs-url`, and a plugin whose store is not
named refuses to run.

`unifi-syslog` trusts nothing in a line: the lines come over plain UDP with nothing to say
who sent them, so the sender's address is kept on every record, and a line of a shape
nobody mapped is stored with its text whole. Its parser is fuzzed (`FuzzParse`), and its
fixtures, `internal/plugins/unifisyslog/testdata`, hold one line per shape a device sends,
every name and address in them a placeholder.

## Working on it

```bash
just lint       # the shared limen baseline and the Go lane
just test       # the plugins against a stand-in modem and stand-in stores
just security   # the shared scans, the link check and the Go vulnerability scan
just fix        # repair what `just lint` reports
```

`just --list` shows the rest.
