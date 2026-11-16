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
read, each sample labelled with its plugin's name as `job`. While the store is down, every
read made in that time is lost.

## Working on it

```bash
just lint       # the shared limen baseline and the Go lane
just test       # the plugins against a stand-in modem and a stand-in store
just security   # the shared scans, the link check and the Go vulnerability scan
just fix        # repair what `just lint` reports
```

`just --list` shows the rest.
