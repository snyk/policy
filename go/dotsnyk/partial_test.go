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
			Ignore:  dotsnyk.RuleSet{},
			Patch:   dotsnyk.RuleSet{},
			Warnings: []dotsnyk.Warning{&dotsnyk.SkippedRule{
				Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 6,
				Reason: "disregardIfFixable: cannot unmarshal !!str `maybe` into bool",
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
			Ignore: dotsnyk.RuleSet{vulnCXCT: {{
				"*":               {Reason: ptr("kept")},
				"a,b":             {Reason: ptr("joined")},
				"[object Object]": {Reason: ptr("an object")},
			}}},
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
			Ignore: dotsnyk.RuleSet{vulnCXCT: {{
				"a > b": {Reason: ptr("valid"), Expires: ptr(expires2099)},
				"c > d": {},
				"e > f": {Reason: ptr("kept without author")},
			}}},
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
}
