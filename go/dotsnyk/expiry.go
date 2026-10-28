package dotsnyk

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	tagBool      = "!!bool"
	tagInt       = "!!int"
	tagFloat     = "!!float"
	tagTimestamp = "!!timestamp"
	tagStr       = "!!str"
)

const jsJSONLayout = "2006-01-02T15:04:05.000Z"

var (
	earliestJSONTime = time.Date(0, time.January, 1, 0, 0, 0, 0, time.UTC)
	latestJSONTime   = time.Date(9999, time.December, 31, 23, 59, 59, 999_000_000, time.UTC)
)

var (
	jsYAMLBools = []string{"true", "True", "TRUE", "false", "False", "FALSE"}
	jsYAMLInt   = regexp.MustCompile(`^[-+]?(?:0|0b[01_]*[01]|0x[\da-fA-F_]*[\da-fA-F]|0[0-7_]*[0-7]` +
		`|[1-9](?:[\d_]*\d)?|[1-9][\d_]*(?::[0-5]?\d)+)$`)
	jsYAMLFloat = regexp.MustCompile(`^(?:[-+]?(?:0|[1-9][\d_]*)(?:\.[\d_]*)?(?:[eE][-+]?\d+)?` +
		`|\.[\d_]+(?:[eE][-+]?\d+)?` +
		`|[-+]?\d[\d_]*(?::[0-5]?\d)+\.[\d_]*` +
		`|[-+]?\.(?:inf|Inf|INF)` +
		`|\.(?:nan|NaN|NAN))$`)
	jsYAMLDate      = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})$`)
	jsYAMLTimestamp = regexp.MustCompile(`^(\d{4})-(\d\d?)-(\d\d?)` +
		`(?:[Tt]|[ \t]+)(\d\d?):(\d{2}):(\d{2})` +
		`(?:\.(\d*))?` +
		`(?:[ \t]*(Z|([-+])(\d\d?)(?::(\d{2}))?))?$`)
)

type expiry struct {
	at          *time.Time
	reason      string
	nonStandard bool
}

type expiryKey struct {
	value, tag  string
	style       yaml.Style
	nonSpecific bool
}

func (d *policyDecoder) expiry(node *yaml.Node) expiry {
	if isNullNode(node) {
		return expiry{}
	}
	if node.Kind != yaml.ScalarNode {
		return expiry{reason: "must be a timestamp, got " + describeNode(node)}
	}
	key := expiryKey{value: node.Value, tag: node.ShortTag(), style: node.Style, nonSpecific: d.hasNonSpecificTag(node)}
	if e, ok := d.expiries[key]; ok {
		return e
	}
	if d.expiries == nil {
		d.expiries = make(map[expiryKey]expiry)
	}
	e := readExpiry(node, key.nonSpecific)
	d.expiries[key] = e
	return e
}

func (d *policyDecoder) hasNonSpecificTag(node *yaml.Node) bool {
	if node.Line < 1 || node.Line > len(d.lines) || node.Column < 1 {
		return false
	}
	line := []rune(d.lines[node.Line-1])
	if node.Column > len(line) {
		return false
	}
	rest := strings.TrimLeft(skipAnchor(string(line[node.Column-1:])), " \t")
	for _, tag := range []string{"!<!>", "!"} {
		if after, ok := strings.CutPrefix(rest, tag); ok {
			return after == "" || strings.ContainsAny(after[:1], " \t\r")
		}
	}
	return false
}

func skipAnchor(text string) string {
	if !strings.HasPrefix(text, "&") {
		return text
	}
	if end := strings.IndexAny(text, " \t"); end >= 0 {
		return text[end:]
	}
	return ""
}

func readExpiry(node *yaml.Node, nonSpecific bool) expiry {
	tag, reason := tagStr, ""
	if !nonSpecific {
		tag, reason = jsYAMLNodeTag(node)
	}
	if reason != "" {
		return expiry{reason: reason}
	}
	var e expiry
	parsed, standard := lenientTimestamp(node.Value)
	switch tag {
	case tagTimestamp:
		e.at = expiryOfDate(jsYAMLTimestampValue(node.Value))
	case tagStr:
		if standard && textExpiresWithinASecondOf(node.Value, parsed) {
			e.at = &parsed
		} else {
			e.at = expiryOfText(node.Value)
		}
	}
	e.nonStandard = !standard || e.at == nil || !e.at.Equal(parsed)
	return e
}

func textExpiresWithinASecondOf(text string, parsed time.Time) bool {
	lastBefore := parsed.Add(-time.Nanosecond).Truncate(time.Millisecond)
	return jsJSON(lastBefore) <= text && jsJSON(parsed.Add(time.Second)) > text
}

func jsJSON(t time.Time) string {
	return t.UTC().Format(jsJSONLayout)
}

func jsYAMLNodeTag(node *yaml.Node) (tag, reason string) {
	implicit := tagStr
	if node.Style&^yaml.TaggedStyle == 0 {
		implicit = jsYAMLTag(node.Value)
	}
	if node.Style&yaml.TaggedStyle == 0 {
		return implicit, ""
	}
	explicit := node.ShortTag()
	if explicit == tagStr || slices.ContainsFunc(jsYAMLImplicitTypes, func(t jsYAMLType) bool {
		return t.tag == explicit && t.resolves(node.Value)
	}) {
		return explicit, ""
	}
	return "", fmt.Sprintf("'%s' is tagged %s", node.Value, explicit)
}

type jsYAMLType struct {
	tag      string
	resolves func(string) bool
}

var jsYAMLImplicitTypes = []jsYAMLType{
	{tag: tagNull, resolves: func(v string) bool { return slices.Contains(nullValues, v) }},
	{tag: tagBool, resolves: func(v string) bool { return slices.Contains(jsYAMLBools, v) }},
	{tag: tagInt, resolves: jsYAMLInt.MatchString},
	{tag: tagFloat, resolves: func(v string) bool { return jsYAMLFloat.MatchString(v) && !strings.HasSuffix(v, "_") }},
	{tag: tagTimestamp, resolves: func(v string) bool { return jsYAMLDate.MatchString(v) || jsYAMLTimestamp.MatchString(v) }},
}

func jsYAMLTag(value string) string {
	for _, t := range jsYAMLImplicitTypes {
		if t.resolves(value) {
			return t.tag
		}
	}
	return tagStr
}

func jsYAMLTimestampValue(value string) time.Time {
	if m := jsYAMLDate.FindStringSubmatch(value); m != nil {
		return jsDateUTC(jsDate{year: number(m[1]), month: number(m[2]), day: number(m[3])})
	}

	m := jsYAMLTimestamp.FindStringSubmatch(value)
	date := jsDate{
		year: number(m[1]), month: number(m[2]), day: number(m[3]),
		hour: number(m[4]), minute: number(m[5]), second: number(m[6]),
	}
	if m[7] != "" {
		date.milli = number((m[7] + "00")[:3])
	}
	t := jsDateUTC(date)
	if m[9] != "" {
		offset := time.Duration(number(m[10])*60+number(m[11])) * time.Minute
		if m[9] == "-" {
			offset = -offset
		}
		t = t.Add(-offset)
	}
	return t
}

type jsDate struct {
	year, month, day, hour, minute, second, milli int
}

func jsDateUTC(d jsDate) time.Time {
	if d.year >= 0 && d.year <= 99 {
		d.year += 1900
	}
	return time.Date(d.year, time.Month(d.month), d.day, d.hour, d.minute, d.second, d.milli*int(time.Millisecond), time.UTC)
}

func number(digits string) int {
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0
	}
	return n
}

func expiryOfDate(date time.Time) *time.Time {
	switch {
	case date.Equal(latestJSONTime):
		return nil
	case date.After(latestJSONTime):
		date = earliestJSONTime
	}
	return &date
}

func expiryOfText(text string) *time.Time {
	if text == "" || jsJSON(latestJSONTime) <= text {
		return nil
	}
	lo, hi := earliestJSONTime.UnixMilli(), latestJSONTime.UnixMilli()
	for lo < hi {
		mid := lo + (hi-lo)/2
		if jsJSON(time.UnixMilli(mid)) > text {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	expires := time.UnixMilli(lo).UTC()
	return &expires
}

func lenientTimestamp(value string) (time.Time, bool) {
	for _, layout := range lenientTimeFormats {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
