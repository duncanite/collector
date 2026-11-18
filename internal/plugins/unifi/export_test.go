package unifi

import (
	"time"

	"github.com/duncanite/go-unifi/console"

	"github.com/duncanite/collector/internal/plugin"
)

// Series is the series one reading of the console becomes, for the tests
// of what its documents are made into.
func Series(devices, clients, health []console.Document, now time.Time) []plugin.Sample {
	return samples(reading{devices: devices, clients: clients, health: health}, now)
}
