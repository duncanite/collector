// collector is the house's one door for telemetry: it listens to or asks
// each source a deployment enables, and hands what it gets to the stores.
// Every source is a plugin compiled in below; --enable names the ones that
// run.
package main

import (
	"context"
	"os"

	"github.com/mycophonic/primordium/app"
	"github.com/mycophonic/primordium/app/shutdown"

	"github.com/duncanite/collector/internal/cli"
	"github.com/duncanite/collector/internal/plugin"
	"github.com/duncanite/collector/internal/plugins/arris"
	"github.com/duncanite/collector/internal/plugins/unifisyslog"
)

func main() {
	app.Main(&app.Options{Name: "collector"}, func(ctx context.Context) error {
		// Every plugin this build holds. A new source is one more line.
		plugins := []plugin.Plugin{
			arris.New(),
			unifisyslog.New(),
		}

		if code := cli.Run(ctx, os.Args[1:], os.Stderr, plugins...); code != cli.ExitOK {
			return shutdown.ExitError(code)
		}

		return nil
	})
}
