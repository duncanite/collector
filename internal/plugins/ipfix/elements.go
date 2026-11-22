package ipfix

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// own heads the name of every field that is IPFIX's and nobody else's:
// IANA's name of the element after it, or its number when it has none here.
const own = "ipfix."

// The fields OpenTelemetry has a name for, as the syslog plugin writes them
// for a firewall line: one query finds an address in both.
const (
	sourceAddress      = "source.address"
	sourcePort         = "source.port"
	destinationAddress = "destination.address"
	destinationPort    = "destination.port"
	transport          = "network.transport"
)

// What is kept of one value: a string an exporter writes is cut at
// mostText octets, and octets nobody here can read at mostOpaque.
const (
	mostText   = 256
	mostOpaque = 64
)

// The sizes the readings below take.
const (
	wide      = 8  // the widest unsigned, and a time in milliseconds or NTP's
	narrow    = 4  // a time in seconds
	hardware  = 6  // a MAC address
	inet      = 4  // an IPv4 address
	inetSix   = 16 // an IPv6 address
	halfBits  = 32
	sinceNTP  = 2208988800 // seconds from 1900, NTP's start, to 1970
	perSecond = 1_000_000_000
)

// The elements this package reads for more than their name.
const (
	octetDeltaCount             = 1
	packetDeltaCount            = 2
	protocolIdentifier          = 4
	sourceTransportPort         = 7
	sourceIPv4Address           = 8
	destinationTransportPort    = 11
	destinationIPv4Address      = 12
	sourceIPv6Address           = 27
	destinationIPv6Address      = 28
	flowEndSeconds              = 151
	flowEndMilliseconds         = 153
	flowEndMicroseconds         = 155
	flowEndNanoseconds          = 157
	observationTimeMilliseconds = 323
	observationTimeMicroseconds = 324
	observationTimeNanoseconds  = 325
)

// kind is how an element's octets are read.
type kind uint8

const (
	// opaque is octets with no reading here: written in hex.
	opaque kind = iota
	// unsigned is a number of one to eight octets: an exporter may send
	// one in fewer than its element has.
	unsigned
	// protocol is the number of an IP protocol, written as its name when
	// it is one of the few a house sees.
	protocol
	// address is an IPv4 or an IPv6 address.
	address
	// link is a MAC address.
	link
	// text is a string.
	text
	// seconds and milliseconds are a time since 1970.
	seconds
	milliseconds
	// fraction is a time as NTP writes it, seconds since 1900 and a
	// fraction of one: IPFIX's micro- and nanoseconds.
	fraction
)

// element is one of IANA's information elements: the field it is written
// under, and how it is read.
type element struct {
	name string
	kind kind
}

// elements is the part of IANA's registry a gateway exports
// (https://www.iana.org/assignments/ipfix), by element number. An element
// that is not here is written in hex under its number.
//
//nolint:gochecknoglobals // the registry's table
var elements = map[uint16]element{
	octetDeltaCount:             {own + "octetDeltaCount", unsigned},
	packetDeltaCount:            {own + "packetDeltaCount", unsigned},
	protocolIdentifier:          {transport, protocol},
	5:                           {own + "ipClassOfService", unsigned},
	6:                           {own + "tcpControlBits", unsigned},
	sourceTransportPort:         {sourcePort, unsigned},
	sourceIPv4Address:           {sourceAddress, address},
	9:                           {own + "sourceIPv4PrefixLength", unsigned},
	10:                          {own + "ingressInterface", unsigned},
	destinationTransportPort:    {destinationPort, unsigned},
	destinationIPv4Address:      {destinationAddress, address},
	13:                          {own + "destinationIPv4PrefixLength", unsigned},
	14:                          {own + "egressInterface", unsigned},
	15:                          {own + "ipNextHopIPv4Address", address},
	21:                          {own + "flowEndSysUpTime", unsigned},
	22:                          {own + "flowStartSysUpTime", unsigned},
	sourceIPv6Address:           {sourceAddress, address},
	destinationIPv6Address:      {destinationAddress, address},
	29:                          {own + "sourceIPv6PrefixLength", unsigned},
	30:                          {own + "destinationIPv6PrefixLength", unsigned},
	31:                          {own + "flowLabelIPv6", unsigned},
	32:                          {own + "icmpTypeCodeIPv4", unsigned},
	33:                          {own + "igmpType", unsigned},
	34:                          {own + "samplingInterval", unsigned},
	35:                          {own + "samplingAlgorithm", unsigned},
	56:                          {own + "sourceMacAddress", link},
	57:                          {own + "postDestinationMacAddress", link},
	58:                          {own + "vlanId", unsigned},
	59:                          {own + "postVlanId", unsigned},
	60:                          {own + "ipVersion", unsigned},
	61:                          {own + "flowDirection", unsigned},
	62:                          {own + "ipNextHopIPv6Address", address},
	80:                          {own + "destinationMacAddress", link},
	81:                          {own + "postSourceMacAddress", link},
	82:                          {own + "interfaceName", text},
	83:                          {own + "interfaceDescription", text},
	85:                          {own + "octetTotalCount", unsigned},
	86:                          {own + "packetTotalCount", unsigned},
	89:                          {own + "forwardingStatus", unsigned},
	130:                         {own + "exporterIPv4Address", address},
	131:                         {own + "exporterIPv6Address", address},
	136:                         {own + "flowEndReason", unsigned},
	139:                         {own + "icmpTypeCodeIPv6", unsigned},
	144:                         {own + "exportingProcessId", unsigned},
	148:                         {own + "flowId", unsigned},
	150:                         {own + "flowStartSeconds", seconds},
	flowEndSeconds:              {own + "flowEndSeconds", seconds},
	152:                         {own + "flowStartMilliseconds", milliseconds},
	flowEndMilliseconds:         {own + "flowEndMilliseconds", milliseconds},
	154:                         {own + "flowStartMicroseconds", fraction},
	flowEndMicroseconds:         {own + "flowEndMicroseconds", fraction},
	156:                         {own + "flowStartNanoseconds", fraction},
	flowEndNanoseconds:          {own + "flowEndNanoseconds", fraction},
	160:                         {own + "systemInitTimeMilliseconds", milliseconds},
	176:                         {own + "icmpTypeIPv4", unsigned},
	177:                         {own + "icmpCodeIPv4", unsigned},
	178:                         {own + "icmpTypeIPv6", unsigned},
	179:                         {own + "icmpCodeIPv6", unsigned},
	192:                         {own + "ipTTL", unsigned},
	209:                         {own + "tcpOptions", unsigned},
	225:                         {own + "postNATSourceIPv4Address", address},
	226:                         {own + "postNATDestinationIPv4Address", address},
	227:                         {own + "postNAPTSourceTransportPort", unsigned},
	228:                         {own + "postNAPTDestinationTransportPort", unsigned},
	229:                         {own + "natOriginatingAddressRealm", unsigned},
	230:                         {own + "natEvent", unsigned},
	231:                         {own + "initiatorOctets", unsigned},
	232:                         {own + "responderOctets", unsigned},
	239:                         {own + "biflowDirection", unsigned},
	256:                         {own + "ethernetType", unsigned},
	281:                         {own + "postNATSourceIPv6Address", address},
	282:                         {own + "postNATDestinationIPv6Address", address},
	298:                         {own + "initiatorPackets", unsigned},
	299:                         {own + "responderPackets", unsigned},
	observationTimeMilliseconds: {own + "observationTimeMilliseconds", milliseconds},
	observationTimeMicroseconds: {own + "observationTimeMicroseconds", fraction},
	observationTimeNanoseconds:  {own + "observationTimeNanoseconds", fraction},
}

// protocols names the IP protocols as a firewall line of the gateway's
// does, so that a flow and the line of its first packet read alike; any
// other is written as its number.
//
//nolint:gochecknoglobals // the few names
var protocols = map[uint64]string{
	1:  "icmp",
	6:  "tcp",
	17: "udp",
	58: "icmpv6",
}

// read is value as the kind reads it, and the time it holds when it is
// one. Octets of a length the kind does not come in are written in hex:
// an exporter that sends an address of five octets is not believed, and
// not lost either.
func (k kind) read(value []byte) (string, time.Time) {
	switch k {
	case unsigned:
		if number, ok := number(value); ok {
			return strconv.FormatUint(number, 10), time.Time{}
		}
	case protocol:
		if number, ok := number(value); ok {
			if name, named := protocols[number]; named {
				return name, time.Time{}
			}

			return strconv.FormatUint(number, 10), time.Time{}
		}
	case address:
		if at, ok := netip.AddrFromSlice(value); ok {
			return at.String(), time.Time{}
		}
	case link:
		if len(value) == hardware {
			return net.HardwareAddr(value).String(), time.Time{}
		}
	case text:
		return printable(string(value[:min(len(value), mostText)])), time.Time{}
	case seconds, milliseconds, fraction:
		if at, ok := k.time(value); ok {
			return at.UTC().Format(time.RFC3339Nano), at
		}
	case opaque:
	}

	return hex.EncodeToString(value[:min(len(value), mostOpaque)]), time.Time{}
}

// time is the time value holds, when it is of the kind's size.
func (k kind) time(value []byte) (time.Time, bool) {
	switch {
	case k == seconds && len(value) == narrow:
		return time.Unix(int64(binary.BigEndian.Uint32(value)), 0), true
	case k == milliseconds && len(value) == wide:
		since := binary.BigEndian.Uint64(value)
		if since > math.MaxInt64 {
			return time.Time{}, false
		}

		return time.UnixMilli(int64(since)), true
	case k == fraction && len(value) == wide:
		whole := int64(binary.BigEndian.Uint32(value)) - sinceNTP
		part := int64(binary.BigEndian.Uint32(value[narrow:])) * perSecond >> halfBits

		return time.Unix(whole, part), true
	}

	return time.Time{}, false
}

// number is an unsigned of one to eight octets, the most significant
// first.
func number(value []byte) (uint64, bool) {
	if len(value) == 0 || len(value) > wide {
		return 0, false
	}

	var padded [wide]byte

	copy(padded[wide-len(value):], value)

	return binary.BigEndian.Uint64(padded[:]), true
}

// printable is text with what is not UTF-8, and every control character
// but the tab and the line feed, replaced: an escape sequence or a NUL an
// exporter put in a name is not handed to whoever prints the store's
// lines.
func printable(text string) string {
	return strings.Map(func(char rune) rune {
		if unicode.IsControl(char) && char != '\t' && char != '\n' {
			return utf8.RuneError
		}

		return char
	}, strings.ToValidUTF8(text, string(utf8.RuneError)))
}
