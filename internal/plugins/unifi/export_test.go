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

// Tell tells names what one reading of the console, made at now by a
// plugin that reads every interval, says of who each address is.
func Tell(names *plugin.Names, devices, clients []console.Document, now time.Time, interval time.Duration) {
	announce(names, reading{devices: devices, clients: clients}, now, interval)
}
