package unifi

import (
	"net/netip"
	"time"

	"github.com/duncanite/go-unifi/console"

	"github.com/duncanite/collector/internal/plugin"
)

// Series is the series one reading of the console becomes, for the tests
// of what its documents are made into.
func Series(devices, clients, health []console.Document, now time.Time) []plugin.Sample {
	return samples(reading{devices: devices, clients: clients, health: health}, now)
}

// Addresses is who each address of one reading of the console is, for the
// tests of what the plugin tells the others.
func Addresses(devices, clients []console.Document) map[netip.Addr]string {
	return whoIsWhere(reading{devices: devices, clients: clients})
}
