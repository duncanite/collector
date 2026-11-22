package plugin_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/duncanite/collector/internal/plugin"
)

// noon is when the tests' names are asked.
func noon() time.Time { return time.Date(2026, time.November, 22, 12, 0, 0, 0, time.UTC) }

func at(text string) netip.Addr { return netip.MustParseAddr(text) }

func TestAnAddressIsCalledWhatItsTellerStandsBy(t *testing.T) {
	t.Parallel()

	names := plugin.NewNames()
	names.Tell("console", map[netip.Addr]string{at("192.0.2.7"): "Laptop"}, noon())

	if got := names.Of(at("192.0.2.7"), noon()); got != "Laptop" {
		t.Errorf("at the last moment of its word the address is %q, want Laptop", got)
	}

	if got := names.Of(at("192.0.2.7"), noon().Add(time.Nanosecond)); got != "" {
		t.Errorf("past its teller's word the address is %q, want nobody", got)
	}

	if got := names.Of(at("192.0.2.8"), noon()); got != "" {
		t.Errorf("an address nobody named is %q", got)
	}
}

func TestWhatIsToldTakesThePlaceOfWhatWas(t *testing.T) {
	t.Parallel()

	names := plugin.NewNames()
	told := map[netip.Addr]string{at("192.0.2.7"): "Laptop"}

	names.Tell("console", told, noon())

	// The map is the teller's own again once told.
	told[at("192.0.2.7")] = "Changed"

	if got := names.Of(at("192.0.2.7"), noon()); got != "Laptop" {
		t.Errorf("the address is %q, want what was told, Laptop", got)
	}

	names.Tell("console", map[netip.Addr]string{at("192.0.2.8"): "Thermostat"}, noon())

	if got := names.Of(at("192.0.2.7"), noon()); got != "" {
		t.Errorf("an address the teller no longer names is %q", got)
	}

	if got := names.Of(at("192.0.2.8"), noon()); got != "Thermostat" {
		t.Errorf("the address told last is %q, want Thermostat", got)
	}
}

func TestTheFirstTellerByNameIsHeardWhileItStandsByItsWord(t *testing.T) {
	t.Parallel()

	names := plugin.NewNames()

	// Told in the other order than they are heard.
	names.Tell("b", map[netip.Addr]string{at("192.0.2.7"): "from b", at("192.0.2.8"): "only b"}, noon().Add(time.Hour))
	names.Tell("a", map[netip.Addr]string{at("192.0.2.7"): "from a"}, noon())

	for address, want := range map[string]string{"192.0.2.7": "from a", "192.0.2.8": "only b"} {
		if got := names.Of(at(address), noon()); got != want {
			t.Errorf("%s is %q, want %q", address, got, want)
		}
	}

	if got := names.Of(at("192.0.2.7"), noon().Add(time.Minute)); got != "from b" {
		t.Errorf("once a no longer stands by its word the address is %q, want from b", got)
	}
}

func TestAnAddressIsOneHoweverItIsWritten(t *testing.T) {
	t.Parallel()

	names := plugin.NewNames()
	names.Tell("console", map[netip.Addr]string{
		at("::ffff:192.0.2.7"): "Laptop",
		at("192.0.2.8"):        "Thermostat",
		at("2001:db8::1"):      "Printer",
	}, noon())

	for address, want := range map[string]string{
		"192.0.2.7":        "Laptop",
		"::ffff:192.0.2.8": "Thermostat",
		"2001:db8::1":      "Printer",
	} {
		if got := names.Of(at(address), noon()); got != want {
			t.Errorf("%s is %q, want %q", address, got, want)
		}
	}
}

func TestWhatNamesNobodyIsNotKept(t *testing.T) {
	t.Parallel()

	names := plugin.NewNames()
	names.Tell("console", map[netip.Addr]string{{}: "No address", at("192.0.2.7"): ""}, noon())

	for _, address := range []netip.Addr{{}, at("192.0.2.7")} {
		if got := names.Of(address, noon()); got != "" {
			t.Errorf("%v is %q, want nobody", address, got)
		}
	}
}

func TestNoNamesAtAllKnowNobodyAndTakeNothing(t *testing.T) {
	t.Parallel()

	var names *plugin.Names

	names.Tell("console", map[netip.Addr]string{at("192.0.2.7"): "Laptop"}, noon())

	if got := names.Of(at("192.0.2.7"), noon()); got != "" {
		t.Errorf("with no names the address is %q", got)
	}
}
