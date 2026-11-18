package unifisyslog

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// cefHead is how a CEF event starts, after the host: "CEF:<version>|".
var cefHead = regexp.MustCompile(`^CEF:(\d+)\|`)

// cefKey is where an extension starts: a key and its "=", at the head of
// the extensions or after a space. A "=" inside a value is written "\=",
// which this does not match, the backslash not being of a key.
var cefKey = regexp.MustCompile(`(?:^| )([A-Za-z0-9_.-]+)=`)

// The header's fields after the version, in their order, and how many
// there are: the extensions follow the last.
//
//nolint:gochecknoglobals // the header's shape
var cefHeader = [...]string{
	"cef.device_vendor", "cef.device_product", "cef.device_version",
	"cef.device_event_class_id", "cef.name", "cef.severity",
}

// Where the product and the severity stand in the header.
const (
	product  = 1
	severity = 5
)

// most is how many extensions of an event become fields. The console's
// own events carry some thirty-five; a line with more is not the
// console's, and every name it brings is one more the store keeps.
const most = 64

// CEF's severity runs from 0 to 10; these are where syslog's keywords
// take over from one another.
const (
	cefWarning  = 4
	cefError    = 7
	cefCritical = 9
)

func isCEF(rest string) bool { return cefHead.MatchString(rest) }

// cef reads a console event: the header's fields and every extension are
// kept under cef.*, the event's sentence (msg) becomes the body, its own
// time (UNIFIutcTime, to the millisecond) the record's when it is within a
// day of the reading, CEF's severity the record's, and the product the
// service.
func (r *record) cef(rest string) {
	match := cefHead.FindStringSubmatch(rest)
	r.add("cef.version", match[1])

	header, extensions, whole := cefSplit(rest[len(match[0]):])
	if !whole {
		// Not the header CEF promises: kept whole, as the body already is.
		return
	}

	for index, value := range header {
		r.add(cefHeader[index], value)
	}

	r.add("service.name", header[product])
	r.Severity = cefSeverity(header[severity], r.Severity)

	found := cefExtensions(extensions)
	// An event with more extensions than the console writes keeps its
	// text whole, and gives the first of them and no more.
	whole = len(found) <= most

	for _, extension := range found[:min(len(found), most)] {
		switch extension.key {
		case "msg":
			if whole {
				r.Body = extension.value
			}

			continue
		case "UNIFIutcTime":
			// The event's own time, to the millisecond, when it is near
			// the reading; what it says stays in the field either way.
			if at, err := time.Parse(time.RFC3339Nano, extension.value); err == nil && near(at, r.received) {
				r.Time = at
			}
		}

		r.add("cef.extensions."+extension.key, extension.value)
	}
}

// cefSeverity is CEF's 0 to 10 as a syslog keyword, or fallback when it is
// not a number.
func cefSeverity(text, fallback string) string {
	level, err := strconv.Atoi(text)

	switch {
	case err != nil:
		return fallback
	case level >= cefCritical:
		return "crit"
	case level >= cefError:
		return "err"
	case level >= cefWarning:
		return "warning"
	default:
		return "info"
	}
}

// cefSplit cuts the header's fields off the head of text, at each "|"
// that is not written "\|", unescapes them, and returns them with what
// follows; whole is false when text ends before the last of them.
func cefSplit(text string) (header [len(cefHeader)]string, rest string, whole bool) {
	var (
		field strings.Builder
		count int
	)

	for index := 0; index < len(text); index++ {
		switch char := text[index]; {
		case char == '\\' && index+1 < len(text) && (text[index+1] == '|' || text[index+1] == '\\'):
			index++
			field.WriteByte(text[index])
		case char == '|':
			header[count] = field.String()
			field.Reset()

			count++
			if count == len(header) {
				return header, text[index+1:], true
			}
		default:
			field.WriteByte(char)
		}
	}

	return header, "", false
}

type cefExtension struct {
	key   string
	value string
}

// cefExtensions reads "key=value key=value": a value runs to the next key,
// so it may hold spaces, and its "\=", "\\", "\n" and "\r" are unescaped.
// Both of the last two become a line feed: CEF means a new line by either,
// and a carriage return is a control character no record holds.
func cefExtensions(text string) []cefExtension {
	starts := cefKey.FindAllStringSubmatchIndex(text, -1)
	extensions := make([]cefExtension, 0, len(starts))

	for index, start := range starts {
		end := len(text)
		if index+1 < len(starts) {
			end = starts[index+1][0]
		}

		extensions = append(extensions, cefExtension{
			key:   text[start[2]:start[3]],
			value: cefUnescape.Replace(text[start[1]:end]),
		})
	}

	return extensions
}

//nolint:gochecknoglobals // a replacer is built once
var cefUnescape = strings.NewReplacer(`\=`, `=`, `\\`, `\`, `\n`, "\n", `\r`, "\n")
