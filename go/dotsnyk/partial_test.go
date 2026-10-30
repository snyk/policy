package dotsnyk_test

import (
	"bytes"
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/policy/go/dotsnyk"
)

const (
	vulnCXCT            = dotsnyk.VulnID("SNYK-JS-CXCT-535487")
	vulnLodash          = dotsnyk.VulnID("SNYK-JS-LODASH-567746")
	vulnLodashPrototype = dotsnyk.VulnID("SNYK-JS-LODASH-590103")
	vulnMinimist        = dotsnyk.VulnID("SNYK-JS-MINIMIST-559764")
)

func TestPolicy_Unmarshal_PartialCases(t *testing.T) {
	var (
		expires2099    = time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
		patched2021    = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
		rolledOver2100 = time.Date(2100, time.February, 14, 0, 0, 0, 0, time.UTC)
	)

	testCases := []struct {
		file string
		want dotsnyk.Policy
	}{{
		file: "bad-timestamp.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{vulnCXCT: {{"*": {Reason: ptr("bad ts")}}}},
			Patch:   dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.NonStandardExpiry{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 6, Value: "not-a-date",
			}},
		},
	}, {
		file: "expires-not-scalar.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{},
			Patch:   dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.SkippedRule{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 7,
				Reason: "expires: must be a timestamp, got a sequence",
			}},
		},
	}, {
		file: "expires-tagged-null.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{},
			Patch:   dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.SkippedRule{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 6,
				Reason: "expires: '2000-01-01' is tagged !!null",
			}},
		},
	}, {
		file: "disregard-not-bool.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {{"*": {
				Reason:             ptr("unclear flag"),
				DisregardIfFixable: ptr(true),
			}}}},
			Patch: dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.CoercedField{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Field: "disregardIfFixable", Line: 6,
				Reason: `"maybe" is not a boolean, read as true`,
			}},
		},
	}, {
		file: "entry-not-mapping.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{},
			Patch:   dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.SkippedRule{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Line: 4,
				Reason: `entry must be a mapping of dependency paths, got scalar "app > cxct"`,
			}},
		},
	}, {
		file: "under-indented-rule.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{vulnLodashPrototype: {{"*": {}}}},
			Warnings: []dotsnyk.Warning{&dotsnyk.SkippedRule{
				Section: dotsnyk.SectionIgnore, VulnID: vulnLodashPrototype, Path: "reason", Line: 5,
				Reason: `dependency path must map to a set of ignore settings, but it is scalar "None Given"; check the indentation`,
			}, &dotsnyk.SkippedRule{
				Section: dotsnyk.SectionIgnore, VulnID: vulnLodashPrototype, Path: "expires", Line: 6,
				Reason: `dependency path must map to a set of ignore settings, but it is scalar "2021-11-21T21:55:08.466Z"; check the indentation`,
			}, &dotsnyk.SkippedRule{
				Section: dotsnyk.SectionIgnore, VulnID: vulnLodashPrototype, Path: "created", Line: 7,
				Reason: `dependency path must map to a set of ignore settings, but it is scalar "2021-10-22T21:55:08.469Z"; check the indentation`,
			}},
		},
	}, {
		file: "path-key-not-string.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {
				{"*": {Reason: ptr("kept")}},
				{"a,b": {Reason: ptr("joined")}},
				{"[object Object]": {Reason: ptr("an object")}},
			}},
			Patch: dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.NonStandardPath{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "a,b", Line: 6,
				Reason: "dependency path is a sequence, so it is read as text",
			}, &dotsnyk.NonStandardPath{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "[object Object]", Line: 8,
				Reason: "dependency path is a mapping, so it is read as text",
			}},
		},
	}, {
		file: "path-is-sequence.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{vulnCXCT: {{"*": {}}}},
			Patch:   dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.NonStandardPath{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 4,
				Reason: "dependency path maps to a sequence, so it applies with no settings",
			}},
		},
	}, {
		file: "aliased-rule-body.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{
				vulnCXCT:   {{"*": {Reason: ptr("shared"), Expires: ptr(expires2099)}}},
				vulnLodash: {{"*": {Reason: ptr("shared"), Expires: ptr(expires2099)}}},
			},
			Patch: dotsnyk.RuleSet{},
		},
	}, {
		file: "sibling-paths.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {
				{"a > b": {Reason: ptr("valid"), Expires: ptr(expires2099)}},
				{"c > d": {}},
				{"e > f": {Reason: ptr("kept without author")}},
			}},
			Patch: dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.DroppedField{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "c > d", Field: "created", Line: 8,
				Reason: "'last tuesday' is not a valid timestamp",
			}, &dotsnyk.NonStandardExpiry{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "c > d", Line: 9, Value: "soon",
			}, &dotsnyk.DroppedField{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "e > f", Field: "ignoredBy", Line: 12,
				Reason: "cannot unmarshal !!str `someone`",
			}},
		},
	}, {
		file: "split-paths-skipped.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {
				{"app > c": {}},
				{"app > b": {Reason: ptr("moved after the other items")}},
				{"app > d": {Reason: ptr("under-indented path read as its own")}},
			}},
			Patch: dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.SkippedRule{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "app > a", Line: 4,
				Reason: `dependency path must map to a set of ignore settings, but it is scalar "not a mapping"; check the indentation`,
			}, &dotsnyk.SkippedRule{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "reason", Line: 8,
				Reason: `dependency path must map to a set of ignore settings, but it is scalar "under-indented"; check the indentation`,
			}},
		},
	}, {
		file: "shared-anchor.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{
				vulnCXCT:     {{"*": {Reason: ptr("shared and broken")}}},
				vulnLodash:   {{"*": {Reason: ptr("shared and broken")}}},
				vulnMinimist: {{"*": {Reason: ptr("shared and broken")}}},
			},
			Patch: dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.NonStandardExpiry{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 7, Value: "soon",
			}, &dotsnyk.NonStandardExpiry{
				Section: dotsnyk.SectionIgnore, VulnID: vulnLodash, Path: "*", Line: 7, Value: "soon",
			}, &dotsnyk.NonStandardExpiry{
				Section: dotsnyk.SectionIgnore, VulnID: vulnMinimist, Path: "*", Line: 7, Value: "soon",
			}},
		},
	}, {
		file: "ignored-by-scalar.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{vulnLodashPrototype: {{"*": {}}}},
			Warnings: []dotsnyk.Warning{&dotsnyk.DroppedField{
				Section: dotsnyk.SectionIgnore, VulnID: vulnLodashPrototype, Path: "*", Field: "ignoredBy", Line: 5,
				Reason: "cannot unmarshal !!str `someone`",
			}},
		},
	}, {
		file: "descriptive-fields.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {{"*": {
				ReasonType: ptr(dotsnyk.ReasonTypeWontFix),
				Expires:    ptr(expires2099),
			}}}},
			Patch: dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.DroppedField{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Field: "reason", Line: 6,
				Reason: "cannot unmarshal !!seq into string",
			}, &dotsnyk.DroppedField{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Field: "created", Line: 9,
				Reason: "'last tuesday' is not a valid timestamp",
			}, &dotsnyk.DroppedField{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Field: "ignoredBy", Line: 10,
				Reason: "cannot unmarshal !!str `someone`",
			}},
		},
	}, {
		file: "mixed.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{
				vulnCXCT: {
					{"*": {Reason: ptr("valid"), Expires: ptr(expires2099)}},
					{"app > cxct": {Reason: ptr("invalid expiry"), Expires: ptr(rolledOver2100)}},
				},
				vulnLodash: {{"*": {
					Reason:    ptr("valid"),
					IgnoredBy: &dotsnyk.IgnoredBy{Email: ptr("someone@example.com")},
				}}},
				vulnMinimist: {{"*": {Reason: ptr("valid, with an unreadable author")}}},
			},
			Patch: dotsnyk.RuleSet{
				vulnLodash: {{"app > lodash": {Patched: ptr(patched2021)}}},
			},
			Warnings: []dotsnyk.Warning{&dotsnyk.NonStandardExpiry{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "app > cxct", Line: 9,
				Value: "2099-13-45", Expires: ptr(rolledOver2100),
			}, &dotsnyk.DroppedField{
				Section: dotsnyk.SectionIgnore, VulnID: vulnMinimist, Path: "*", Field: "ignoredBy", Line: 18,
				Reason: "cannot unmarshal !!str `someone`",
			}, &dotsnyk.SkippedRule{
				Section: dotsnyk.SectionPatch, VulnID: vulnLodash, Line: 23,
				Reason: `entry must be a mapping of dependency paths, got scalar "app > lodash > nested"`,
			}},
		},
	}, {
		file: "alias.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{
				vulnCXCT:   {{"*": {Reason: ptr("shared reason"), Expires: ptr(expires2099)}}},
				vulnLodash: {{"*": {Reason: ptr("shared reason")}}},
			},
			Patch: dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.NonStandardExpiry{
				Section: dotsnyk.SectionIgnore, VulnID: vulnLodash, Path: "*", Line: 10, Value: "soon",
			}},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := partialCases.ReadFile(path.Join(partialDir, tc.file))
			require.NoError(t, err)

			p, err := dotsnyk.Unmarshal(bytes.NewReader(data))
			require.NoError(t, err)

			assert.Equal(t, tc.want, *p)
		})
	}

	covered := make([]string, 0, len(testCases))
	for _, tc := range testCases {
		covered = append(covered, tc.file)
	}
	assertEveryCaseIsCovered(t, partialCases, partialDir, covered)
}

func TestPolicy_Unmarshal_ReadsDisregardIfFixableAsSnykPolicyDoes(t *testing.T) {
	testCases := []struct {
		value   string
		want    *bool
		warning string
	}{
		{value: "true", want: ptr(true)},
		{value: "False", want: ptr(false)},
		{value: "~", want: nil},
		{value: "''", want: nil},
		{value: "'false'", want: ptr(true), warning: `"false" is not a boolean, read as true`},
		{value: "no", want: ptr(true), warning: `"no" is not a boolean, read as true`},
		{value: "off", want: ptr(true), warning: `"off" is not a boolean, read as true`},
		{value: "yes", want: ptr(true), warning: `"yes" is not a boolean, read as true`},
		{value: "'0'", want: ptr(true), warning: `"0" is not a boolean, read as true`},
		{value: "1", want: ptr(true), warning: `"1" is not a boolean, read as true`},
		{value: "0", want: ptr(false), warning: `"0" is not a boolean, read as false`},
		{value: "0x0", want: ptr(false), warning: `"0x0" is not a boolean, read as false`},
		{value: "0.0", want: ptr(false), warning: `"0.0" is not a boolean, read as false`},
		{value: ".nan", want: ptr(false), warning: `".nan" is not a boolean, read as false`},
		{value: "0.5", want: ptr(true), warning: `"0.5" is not a boolean, read as true`},
		{value: ".0", want: ptr(false), warning: `".0" is not a boolean, read as false`},
		{value: "0_0", want: ptr(false), warning: `"0_0" is not a boolean, read as false`},
		{value: "0o0", want: ptr(true), warning: `"0o0" is not a boolean, read as true`},
		{value: "+.0", want: ptr(true), warning: `"+.0" is not a boolean, read as true`},
		{value: "0:00.0", want: ptr(false), warning: `"0:00.0" is not a boolean, read as false`},
		{value: "00.0", want: ptr(true), warning: `"00.0" is not a boolean, read as true`},
		{value: "0_", want: ptr(true), warning: `"0_" is not a boolean, read as true`},
		{value: "0x_", want: ptr(true), warning: `"0x_" is not a boolean, read as true`},
		{value: "1e-400", want: ptr(false), warning: `"1e-400" is not a boolean, read as false`},
		{value: "! 0", want: ptr(true), warning: `"0" is not a boolean, read as true`},
		{value: "!!js/undefined x", want: ptr(false), warning: `"x" is not a boolean, read as false`},
		{value: "!!str 0", want: ptr(true), warning: `"0" is not a boolean, read as true`},
		{value: "2030-01-01", want: ptr(true), warning: `"2030-01-01" is not a boolean, read as true`},
		{value: "[]", want: ptr(true), warning: "a sequence is not a boolean, read as true"},
		{value: "{}", want: ptr(true), warning: "a mapping is not a boolean, read as true"},
	}

	for _, tc := range testCases {
		t.Run(tc.value, func(t *testing.T) {
			assert.Equal(t, policyWithDisregardIfFixable(tc.want, tc.warning), *unmarshalDisregardIfFixable(t, tc.value))
		})
	}
}

func TestPolicy_Unmarshal_ReadsDisregardIfFixableAsTrueWhenSnykPolicyRejectsTheFile(t *testing.T) {
	for _, value := range []string{"!!bool 0", "!!int 0o0", "!!null x", "!foo 0"} {
		t.Run(value, func(t *testing.T) {
			got := unmarshalDisregardIfFixable(t, value)

			assert.Equal(t, ptr(true), got.Ignore[vulnCXCT][0]["*"].DisregardIfFixable)
		})
	}
}

func unmarshalDisregardIfFixable(t *testing.T, value string) *dotsnyk.Policy {
	t.Helper()
	p, err := dotsnyk.Unmarshal(strings.NewReader(
		"ignore:\n  SNYK-JS-CXCT-535487:\n    - '*':\n        disregardIfFixable: " + value + "\n"))
	require.NoError(t, err)
	return p
}

func policyWithDisregardIfFixable(want *bool, warning string) dotsnyk.Policy {
	p := dotsnyk.Policy{Ignore: dotsnyk.RuleSet{vulnCXCT: {{"*": {DisregardIfFixable: want}}}}}
	if warning != "" {
		p.Warnings = []dotsnyk.Warning{&dotsnyk.CoercedField{
			Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Field: "disregardIfFixable", Line: 4,
			Reason: warning,
		}}
	}
	return p
}

func TestPolicy_Unmarshal_RejectsExcessiveAliasing(t *testing.T) {
	var doc strings.Builder
	doc.WriteString("entry: &entry\n")
	for i := range 1000 {
		fmt.Fprintf(&doc, "  'path-%d': {reason: r}\n", i)
	}
	doc.WriteString("entries: &entries [" + strings.Repeat("*entry, ", 99) + "*entry]\n")
	doc.WriteString("ignore:\n")
	for i := range 100 {
		fmt.Fprintf(&doc, "  SNYK-JS-VULN-%d: *entries\n", i)
	}

	_, err := dotsnyk.Unmarshal(strings.NewReader(doc.String()))

	require.EqualError(t, err, "invalid .snyk policy: line 1004: yaml: document contains excessive aliasing")
}

func TestWarning_String(t *testing.T) {
	assert.Equal(t,
		"line 6: skipped ignore rule for SNYK-JS-CXCT-535487 at '*': expires: 'not-a-date' is not a valid timestamp",
		(&dotsnyk.SkippedRule{
			Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 6,
			Reason: "expires: 'not-a-date' is not a valid timestamp",
		}).String())
	assert.Equal(t,
		`line 23: skipped patch rule for SNYK-JS-LODASH-567746: entry must be a mapping of dependency paths, got scalar "x"`,
		(&dotsnyk.SkippedRule{
			Section: dotsnyk.SectionPatch, VulnID: vulnLodash, Line: 23,
			Reason: `entry must be a mapping of dependency paths, got scalar "x"`,
		}).String())
	assert.Equal(t,
		"line 5: dropped ignoredBy from ignore rule for SNYK-JS-LODASH-590103 at '*': cannot unmarshal !!str `someone`",
		(&dotsnyk.DroppedField{
			Section: dotsnyk.SectionIgnore, VulnID: vulnLodashPrototype, Path: "*", Field: "ignoredBy", Line: 5,
			Reason: "cannot unmarshal !!str `someone`",
		}).String())
	assert.Equal(t,
		"line 6: ignore rule for SNYK-JS-CXCT-535487 at '*' never expires: expires: 'soon' is read as the TypeScript implementation reads it",
		(&dotsnyk.NonStandardExpiry{
			Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 6, Value: "soon",
		}).String())
	assert.Equal(t,
		"line 6: ignore rule for SNYK-JS-CXCT-535487 at '*' expires at 2031-01-01T00:00:00Z: expires: '2030/01/01' is read as the TypeScript implementation reads it",
		(&dotsnyk.NonStandardExpiry{
			Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 6, Value: "2030/01/01",
			Expires: ptr(time.Date(2031, time.January, 1, 0, 0, 0, 0, time.UTC)),
		}).String())
	assert.Equal(t,
		"line 4: ignore rule for SNYK-JS-CXCT-535487 at '*' is read as the TypeScript implementation reads it: "+
			"dependency path maps to a sequence, so it applies with no settings",
		(&dotsnyk.NonStandardPath{
			Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 4,
			Reason: "dependency path maps to a sequence, so it applies with no settings",
		}).String())
	assert.Equal(t,
		`line 6: coerced disregardIfFixable in ignore rule for SNYK-JS-CXCT-535487 at '*': "false" is not a boolean, read as true`,
		(&dotsnyk.CoercedField{
			Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Field: "disregardIfFixable", Line: 6,
			Reason: `"false" is not a boolean, read as true`,
		}).String())
}
