package dotsnyk_test

import (
	"bytes"
	"embed"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/policy/go/dotsnyk"
)

func TestPolicy_New(t *testing.T) {
	p := dotsnyk.New()

	assert.NotNil(t, p)
	assert.NotZero(t, p.Version)
	assert.NotNil(t, p.Ignore)
	assert.NotNil(t, p.Patch)
}

func TestPolicy_Marshal(t *testing.T) {
	var buf bytes.Buffer
	p := dotsnyk.New()
	p.Ignore["SNYK-GOLANG-PACKAGE-12345"] = append(p.Ignore["SNYK-GOLANG-PACKAGE-12345"], dotsnyk.RuleEntry{
		"*": {
			Reason:             ptr("none given"),
			DisregardIfFixable: ptr(true),
		},
	})

	err := dotsnyk.Marshal(&buf, p)
	require.NoError(t, err)

	assert.Equal(t, `version: v1.25.1
ignore:
    SNYK-GOLANG-PACKAGE-12345:
        - '*':
            reason: none given
            disregardIfFixable: true
patch: {}
`, buf.String())
}

func TestPolicy_Load(t *testing.T) {
	p, err := dotsnyk.Load("testdata/ignore.yaml")
	require.NoError(t, err)

	assert.NotNil(t, p)
	assert.Equal(t, "v1.0.0", p.Version)
	assert.Len(t, p.Ignore, 5)
	assert.NotNil(t, p.Patch)
	assert.NotNil(t, (*p.Exclude)["global"])
}

const (
	validEmptyDir = "testdata/snyk-cases/validEmpty"
	validDataDir  = "testdata/snyk-cases/validData"
	formattingDir = "testdata/snyk-cases/formatting"
	invalidDir    = "testdata/snyk-cases/invalid"
)

//go:embed testdata/snyk-cases/validEmpty
var validEmptyCases embed.FS

//go:embed testdata/snyk-cases/validData
var validDataCases embed.FS

//go:embed testdata/snyk-cases/formatting
var formattingCases embed.FS

//go:embed testdata/snyk-cases/invalid
var invalidCases embed.FS

func TestPolicy_Unmarshal_ValidEmptyCases(t *testing.T) {
	testCases := []struct {
		file string
		want dotsnyk.Policy
	}{{
		file: "comment-only.snyk",
		want: dotsnyk.Policy{},
	}, {
		file: "empty-maps.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{},
			Patch:   dotsnyk.RuleSet{},
		},
	}, {
		file: "empty-seqs.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{},
			Patch:   dotsnyk.RuleSet{},
		},
	}, {
		file: "empty.snyk",
		want: dotsnyk.Policy{},
	}, {
		file: "explicit-null.snyk",
		want: dotsnyk.Policy{Version: "v1.25.0"},
	}, {
		file: "legacy-ts-default.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{},
			Patch:   dotsnyk.RuleSet{},
		},
	}, {
		file: "no-version.snyk",
		want: dotsnyk.Policy{
			Ignore: dotsnyk.RuleSet{},
			Patch:  dotsnyk.RuleSet{},
		},
	}, {
		file: "null-ignore-patch.snyk",
		want: dotsnyk.Policy{Version: "v1.25.0"},
	}, {
		file: "unknown-keys.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{},
			Patch:   dotsnyk.RuleSet{},
		},
	}, {
		file: "version-only.snyk",
		want: dotsnyk.Policy{Version: "v1.25.0"},
	}, {
		file: "whitespace.snyk",
		want: dotsnyk.Policy{},
	}, {
		file: "whitespace-tab.snyk",
		want: dotsnyk.Policy{},
	}}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := validEmptyCases.ReadFile(path.Join(validEmptyDir, tc.file))
			require.NoError(t, err)

			var p dotsnyk.Policy
			require.NoError(t, dotsnyk.Unmarshal(bytes.NewReader(data), &p))

			assert.Equal(t, tc.want, p)
		})
	}

	covered := make([]string, 0, len(testCases))
	for _, tc := range testCases {
		covered = append(covered, tc.file)
	}
	assertEveryCaseIsCovered(t, validEmptyCases, validEmptyDir, covered)
}

func TestPolicy_Unmarshal_ValidDataCases(t *testing.T) {
	const (
		vulnCXCT   = dotsnyk.VulnID("SNYK-JS-CXCT-535487")
		vulnLodash = dotsnyk.VulnID("SNYK-JS-LODASH-567746")
	)

	var (
		expires2099    = time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
		expires2099Jun = time.Date(2099, time.June, 1, 0, 0, 0, 0, time.UTC)
		expired2020    = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
		created2024    = time.Date(2024, time.January, 15, 9, 0, 0, 0, time.UTC)

		expires2116Milli136 = time.Date(2116, time.March, 1, 14, 30, 4, 136_000_000, time.UTC)
		expires2116Milli137 = time.Date(2116, time.March, 1, 14, 30, 4, 137_000_000, time.UTC)
	)

	testCases := []struct {
		file string
		want dotsnyk.Policy
	}{{
		file: "disregard-if-fixable.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{
				vulnCXCT: {{"*": {
					Reason:             ptr("disregard"),
					Expires:            ptr(expires2099),
					DisregardIfFixable: ptr(true),
				}}},
				vulnLodash: {{"*": {
					Reason:             ptr("do not disregard"),
					Expires:            ptr(expires2099),
					DisregardIfFixable: ptr(false),
				}}},
			},
			Patch: dotsnyk.RuleSet{},
		},
	}, {
		file: "exclude.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{},
			Patch:   dotsnyk.RuleSet{},
			Exclude: &map[string]any{"global": []any{"test/**"}},
		},
	}, {
		file: "expired.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {{"*": {
				Reason:  ptr("already expired"),
				Expires: ptr(expired2020),
			}}}},
			Patch: dotsnyk.RuleSet{},
		},
	}, {
		file: "fail-threshold.snyk",
		want: dotsnyk.Policy{
			Version:       "v1.25.0",
			FailThreshold: ptr(dotsnyk.SeverityHigh),
			Ignore:        dotsnyk.RuleSet{},
			Patch:         dotsnyk.RuleSet{},
		},
	}, {
		file: "ignore-entry-null.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{vulnCXCT: {{"*": {}}}},
			Patch:   dotsnyk.RuleSet{},
		},
	}, {
		file: "multiple-entries.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {
				{"*": {
					Reason:  ptr("wildcard entry"),
					Expires: ptr(expires2099),
				}},
				{"app > cxct": {
					Reason:             ptr("specific entry"),
					Expires:            ptr(expires2099),
					DisregardIfFixable: ptr(true),
				}},
			}},
			Patch: dotsnyk.RuleSet{},
		},
	}, {
		file: "multiple-vulns.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{
				vulnCXCT: {{"*": {
					Reason:  ptr("first vuln"),
					Expires: ptr(expires2099),
					Source:  ptr("cli"),
				}}},
				vulnLodash: {{"*": {
					Reason:  ptr("second vuln"),
					Expires: ptr(expires2099Jun),
					IgnoredBy: &dotsnyk.IgnoredBy{
						ID:    ptr("00000000-0000-0000-0000-000000000001"),
						Name:  ptr("Someone"),
						Email: ptr("s@example.com"),
					},
				}}},
				"npm:hawk:20160119": {{"sqlite > sqlite3 > node-pre-gyp > request > hawk": {
					Reason:  ptr("hawk got bumped"),
					Expires: ptr(expires2116Milli136),
				}}},
				"npm:is-my-json-valid:20160118": {
					{"sqlite > sqlite3 > node-pre-gyp > request > har-validator > is-my-json-valid": {
						Reason:  ptr("dev tool"),
						Expires: ptr(expires2116Milli136),
					}},
				},
				"npm:tar:20151103": {{"sqlite > sqlite3 > node-pre-gyp > tar-pack > tar": {
					Reason:  ptr("none given"),
					Expires: ptr(expires2116Milli137),
				}}},
				"npm:method-override:20170927": {{"*": {
					Reason:             ptr("none given"),
					DisregardIfFixable: ptr(true),
				}}},
				"npm:marked:20170907": {{"*": {
					Reason:             ptr("none given"),
					DisregardIfFixable: ptr(true),
				}}},
			},
			Patch: dotsnyk.RuleSet{},
		},
	}, {
		file: "no-expires.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{vulnCXCT: {{"*": {Reason: ptr("no expiry")}}}},
			Patch:   dotsnyk.RuleSet{},
		},
	}, {
		file: "nonmatching-path.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {{"some-other-pkg": {
				Reason:  ptr("non matching path"),
				Expires: ptr(expires2099),
			}}}},
			Patch: dotsnyk.RuleSet{},
		},
	}, {
		file: "reason-type.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {{"*": {
				Reason:     ptr("rt"),
				ReasonType: ptr(dotsnyk.ReasonTypeWontFix),
				Created:    ptr(created2024),
				Expires:    ptr(expires2099),
				IgnoredBy: &dotsnyk.IgnoredBy{
					Name:  ptr("Someone"),
					Email: ptr("s@example.com"),
				},
			}}}},
			Patch: dotsnyk.RuleSet{},
		},
	}, {
		file: "specific-path.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {{"cxct": {
				Reason:  ptr("specific dep path"),
				Expires: ptr(expires2099),
			}}}},
			Patch: dotsnyk.RuleSet{},
		},
	}, {
		file: "tab-in-block-scalar.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore: dotsnyk.RuleSet{vulnCXCT: {{"*": {
				Reason: ptr("accepted because\n\tthe tab is part of the text\n"),
			}}}},
			Patch: dotsnyk.RuleSet{},
		},
	}, {
		file: "vuln-empty-seq.snyk",
		want: dotsnyk.Policy{
			Version: "v1.25.0",
			Ignore:  dotsnyk.RuleSet{vulnCXCT: {}},
		},
	}}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := validDataCases.ReadFile(path.Join(validDataDir, tc.file))
			require.NoError(t, err)

			var p dotsnyk.Policy
			require.NoError(t, dotsnyk.Unmarshal(bytes.NewReader(data), &p))

			assert.Equal(t, tc.want, p)
		})
	}

	covered := make([]string, 0, len(testCases))
	for _, tc := range testCases {
		covered = append(covered, tc.file)
	}
	assertEveryCaseIsCovered(t, validDataCases, validDataDir, covered)
}

var (
	formattingCreated = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
	formattingExpires = time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
)

func TestPolicy_Unmarshal_FormattingCases(t *testing.T) {
	forEachCase(t, formattingCases, formattingDir, func(t *testing.T, data []byte) {
		t.Helper()

		var p dotsnyk.Policy
		require.NoError(t, dotsnyk.Unmarshal(bytes.NewReader(data), &p))

		assert.Equal(t, "v1.25.0", p.Version)
		assert.Empty(t, p.Patch)
		assert.Nil(t, p.FailThreshold)
		assert.Nil(t, p.Exclude)

		require.Len(t, p.Ignore, 1)
		entries := p.Ignore[dotsnyk.VulnID("SNYK-JS-CXCT-535487")]
		require.Len(t, entries, 1)

		rule, ok := entries[0][("*")]
		require.True(t, ok, "expected an ignore rule for dependency path %q", "*")
		require.NotNil(t, rule)

		require.NotNil(t, rule.Reason)
		assert.Equal(t, "formatting case", *rule.Reason)

		require.NotNil(t, rule.Created)
		assert.True(t, rule.Created.Equal(formattingCreated),
			"created: want %s, got %s", formattingCreated, rule.Created)

		require.NotNil(t, rule.Expires)
		assert.True(t, rule.Expires.Equal(formattingExpires),
			"expires: want %s, got %s", formattingExpires, rule.Expires)

		assert.Nil(t, rule.Patched)
		assert.Nil(t, rule.IgnoredBy)
		assert.Nil(t, rule.ReasonType)
		assert.Nil(t, rule.Source)
		assert.Nil(t, rule.From)
		assert.Nil(t, rule.DisregardIfFixable)
	})
}

func TestPolicy_Unmarshal_InvalidCases(t *testing.T) {
	testCases := []struct {
		file    string
		wantErr string
	}{{
		file:    "malformed-yaml.snyk",
		wantErr: "invalid .snyk policy: yaml: line 1: did not find expected ',' or ']'",
	}, {
		file:    "ignore-scalar.snyk",
		wantErr: `invalid .snyk policy: line 2: rule set must be a mapping, got scalar "nonsense"`,
	}, {
		file:    "ignore-nonempty-seq.snyk",
		wantErr: "invalid .snyk policy: line 3: rule set must be a mapping, got a non-empty sequence",
	}, {
		file:    "vuln-empty-map.snyk",
		wantErr: "old, unsupported .snyk format detected",
	}, {
		file:    "vuln-rule-body.snyk",
		wantErr: "old, unsupported .snyk format detected",
	}, {
		file:    "bad-timestamp.snyk",
		wantErr: "invalid .snyk policy: 'not-a-date' is not a valid timestamp",
	}, {
		file:    "toplevel-scalar.snyk",
		wantErr: `invalid .snyk policy: line 1: policy must be a mapping, got scalar "this is not valid yaml"`,
	}, {
		file:    "toplevel-seq.snyk",
		wantErr: "invalid .snyk policy: line 1: policy must be a mapping, got a sequence",
	}, {
		file:    "tabs.snyk",
		wantErr: "invalid .snyk policy: line 3: invalid indentation",
	}, {
		file:    "tabs-real-ignore.snyk",
		wantErr: "invalid .snyk policy: line 3: invalid indentation",
	}, {
		file:    "tabs-nested.snyk",
		wantErr: "invalid .snyk policy: line 5: invalid indentation",
	}, {
		file: "under-indented-rule.snyk",
		wantErr: `invalid .snyk policy: line 5: dependency path 'reason' must map to a set of ignore settings, ` +
			`but it is scalar "None Given"; check the indentation`,
	}, {
		file:    "ignored-by-scalar.snyk",
		wantErr: "invalid .snyk policy: line 5: cannot unmarshal !!str `someone`",
	}}

	for _, tc := range testCases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := invalidCases.ReadFile(path.Join(invalidDir, tc.file))
			require.NoError(t, err)

			var p dotsnyk.Policy
			err = dotsnyk.Unmarshal(bytes.NewReader(data), &p)

			require.EqualError(t, err, tc.wantErr)
		})
	}

	covered := make([]string, 0, len(testCases))
	for _, tc := range testCases {
		covered = append(covered, tc.file)
	}
	assertEveryCaseIsCovered(t, invalidCases, invalidDir, covered)
}

func assertEveryCaseIsCovered(t *testing.T, cases embed.FS, dir string, covered []string) {
	t.Helper()

	t.Run("every case file is covered", func(t *testing.T) {
		inTable := make(map[string]bool, len(covered))
		for _, file := range covered {
			inTable[file] = true
		}

		entries, err := cases.ReadDir(dir)
		require.NoError(t, err)
		require.NotEmpty(t, entries)

		for _, entry := range entries {
			assert.True(t, inTable[entry.Name()], "%s has no row in the table", entry.Name())
		}
	})
}

func forEachCase(t *testing.T, cases embed.FS, dir string, check func(*testing.T, []byte)) {
	t.Helper()

	entries, err := cases.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		t.Run(entry.Name(), func(t *testing.T) {
			data, readErr := cases.ReadFile(path.Join(dir, entry.Name()))
			require.NoError(t, readErr)

			check(t, data)
		})
	}
}
