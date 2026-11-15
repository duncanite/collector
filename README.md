# collector

The OpenTelemetry Collector of the Duncanite house: the upstream
[contrib distribution](https://github.com/open-telemetry/opentelemetry-collector-releases/tree/v0.165.0/distributions/otelcol-contrib)
with the house's pipelines as its configuration, built here as one image and run on the
house's observability node. Every log and metric of the house enters through it; the stores
behind it are not this repository's.

The repository starts on the shared baseline alone. The configuration, its tests and the
image build arrive one pull request at a time. Nothing here names a host or an address: the
image takes the stores' addresses from its environment.

## Working on it

```bash
just lint       # the shared limen baseline
just security   # the shared scans and the link check
just fix        # repair what `just lint` reports
```

`just --list` shows the rest.
