package plugin

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// mostName is how many octets of a name are kept: more than any host's.
const mostName = 256

// Name is what something on the network is called, made fit to be shown:
// a host chooses its own name, and a name ends up where a browser draws
// it, in a legend or a tooltip that may take it for markup.
//
// It is one line of text and no more: what is not UTF-8, a control
// character, a line or paragraph separator, and a character that only
// formats, the right-to-left override among them, each become U+FFFD;
// "<" and ">" are written "(" and ")", and "&" is written "+", so that no
// tag and no entity is left in it; and it is cut after mostName octets,
// on a character.
func Name(text string) string {
	text = strings.Map(func(char rune) rune {
		switch {
		case char == '<':
			return '('
		case char == '>':
			return ')'
		case char == '&':
			return '+'
		case unicode.IsControl(char),
			unicode.Is(unicode.Cf, char),
			unicode.Is(unicode.Zl, char),
			unicode.Is(unicode.Zp, char):
			return utf8.RuneError
		default:
			return char
		}
	}, strings.ToValidUTF8(text, string(utf8.RuneError)))

	if len(text) <= mostName {
		return text
	}

	// Cut on a character: what is left of one that was cut through is dropped.
	return strings.ToValidUTF8(text[:mostName], "")
}

// Names is what the plugins of one collector tell one another of who an
// address is. A plugin that knows, a console with its list of clients,
// tells; one that only sees addresses, a flow, asks. Nothing is asked of
// the network for it: a name is what a plugin was told by its own source,
// and no lookup leaves the collector.
//
// A nil Names knows nobody and takes nothing: a plugin run without one
// asks and tells all the same.
type Names struct {
	mutex sync.RWMutex
	told  map[string]word
	// tellers is who told something, in the order they are asked: by name,
	// so that two who disagree are heard the same way every time.
	tellers []string
}

// word is what one plugin told: its names, and until when it stands by
// them.
type word struct {
	names map[netip.Addr]string
	until time.Time
}

// NewNames returns the names of nobody yet.
func NewNames() *Names {
	return &Names{told: make(map[string]word)}
}

// Tell replaces everything teller told before with names, which it stands
// by until the given time: an address is handed to another host sooner or
// later, and a teller that goes quiet is not believed for ever. The map is
// copied, and each name is made fit to be shown, as Name does.
func (n *Names) Tell(teller string, names map[netip.Addr]string, until time.Time) {
	if n == nil {
		return
	}

	kept := make(map[netip.Addr]string, len(names))

	for address, name := range names {
		if name = Name(name); address.IsValid() && name != "" {
			kept[address.Unmap()] = name
		}
	}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.told[teller] = word{names: kept, until: until}
	n.tellers = slices.Sorted(maps.Keys(n.told))
}

// Of is what address is called at the given time, or nothing when nobody
// who still stands by its word named it.
func (n *Names) Of(address netip.Addr, when time.Time) string {
	if n == nil || !address.IsValid() {
		return ""
	}

	address = address.Unmap()

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for _, teller := range n.tellers {
		said := n.told[teller]
		if when.After(said.until) {
			continue
		}

		if name, named := said.names[address]; named {
			return name
		}
	}

	return ""
}
