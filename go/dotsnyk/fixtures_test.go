package dotsnyk_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/policy/go/dotsnyk"
)

// The repo's canonical .snyk corpus lives above the Go module root, so go:embed
// cannot reach it. go test runs with the package directory as the working
// directory, so a relative path does.
const repoFixtures = "../../test/fixtures/"

// TestPolicy_Unmarshal_RepoFixtures pins this parser against the fixtures the
// TypeScript implementation in lib/ is tested on, so the two can be compared
// directly. The expectations record what the parser does today, including the
// places where that differs from lib/ — see the parity table in go/README.md.
func TestPolicy_Unmarshal_RepoFixtures(t *testing.T) {
	const (
		hawkPath      = "sqlite > sqlite3 > node-pre-gyp > request > hawk"
		isMyJSONPath  = "sqlite > sqlite3 > node-pre-gyp > request > har-validator > is-my-json-valid"
		tarPath       = "sqlite > sqlite3 > node-pre-gyp > tar-pack > tar"
		vulnHawk      = dotsnyk.VulnID("npm:hawk:20160119")
		vulnHawkUpper = dotsnyk.VulnID("NPM:HAWK:20160119")
		vulnIsMyJSON  = dotsnyk.VulnID("npm:is-my-json-valid:20160118")
		vulnTar       = dotsnyk.VulnID("npm:tar:20151103")
	)

	var (
		expired2024Milli136    = time.Date(2024, time.March, 1, 14, 30, 4, 136_000_000, time.UTC)
		expires2116Milli136    = time.Date(2116, time.March, 1, 14, 30, 4, 136_000_000, time.UTC)
		expires2116Milli137    = time.Date(2116, time.March, 1, 14, 30, 4, 137_000_000, time.UTC)
		expired2000Milli136    = time.Date(2000, time.March, 1, 14, 30, 4, 136_000_000, time.UTC)
		expired2000Milli137    = time.Date(2000, time.March, 1, 14, 30, 4, 137_000_000, time.UTC)
		created2021Milli459    = time.Date(2021, time.July, 26, 13, 9, 8, 459_000_000, time.UTC)
		expired2016FebMilli324 = time.Date(2016, time.February, 19, 11, 25, 17, 324_000_000, time.UTC)
		expired2016FebMilli325 = time.Date(2016, time.February, 19, 11, 25, 17, 325_000_000, time.UTC)
		expired2016MayMilli066 = time.Date(2016, time.May, 24, 13, 46, 19, 66_000_000, time.UTC)
	)

	testCases := []struct {
		name    string
		file    string
		want    dotsnyk.Policy
		wantErr string
	}{{
		name: "ignore",
		file: "ignore/.snyk",
		want: dotsnyk.Policy{
			Version: "v1.0.0",
			Ignore: dotsnyk.RuleSet{
				// Vulnerability IDs are case-sensitive map keys, so the upper-
				// and lower-case spellings of the same ID stay distinct.
				vulnHawkUpper: {{hawkPath: {
					Reason:  ptr("hawk got bumped"),
					Expires: ptr(expired2024Milli136),
				}}},
				vulnHawk: {{hawkPath: {
					Reason:  ptr("hawk got bumped"),
					Expires: ptr(expires2116Milli136),
				}}},
				vulnIsMyJSON: {{isMyJSONPath: {
					Reason:  ptr("dev tool"),
					Expires: ptr(expires2116Milli136),
				}}},
				vulnTar: {{tarPath: {
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
		name: "expired-unquoted",
		file: "ignore-expired-no-quotes/.snyk",
		want: dotsnyk.Policy{
			// An unquoted timestamp is a YAML !!timestamp rather than a string,
			// and the lenient formats accept it all the same.
			Version: "v1",
			Ignore: dotsnyk.RuleSet{
				vulnHawk: {{hawkPath: {
					Reason:  ptr("hawk got bumped"),
					Expires: ptr(expired2000Milli136),
				}}},
				vulnIsMyJSON: {{isMyJSONPath: {
					Reason:  ptr("dev tool"),
					Expires: ptr(expired2000Milli136),
				}}},
				vulnTar: {{tarPath: {
					Reason:  ptr("none given"),
					Expires: ptr(expired2000Milli137),
				}}},
			},
		},
	}, {
		name: "iac",
		file: "ignore-exact/.snyk",
		want: dotsnyk.Policy{
			Version: "v1.19.0",
			Ignore: dotsnyk.RuleSet{"a-vuln": {{"file.json > foo > bar": {
				Reason:  ptr("None Given"),
				Created: ptr(created2021Milli459),
			}}}},
			Patch: dotsnyk.RuleSet{},
		},
	}, {
		name: "mixed-ignore-patch",
		file: "filter-and-track/.snyk",
		want: dotsnyk.Policy{
			Version: "v1.0.0",
			Ignore: dotsnyk.RuleSet{vulnHawk: {{hawkPath: {
				Reason:  ptr("hawk got bumped"),
				Expires: ptr(expires2116Milli136),
			}}}},
			Patch: dotsnyk.RuleSet{vulnTar: {{tarPath: {
				Patched: ptr(expires2116Milli137),
			}}}},
		},
	}, {
		name: "missing-dash",
		file: "issues/SC-1106/missing-dash.snyk",
		want: dotsnyk.Policy{
			// The second path has no leading `-`, so YAML folds it into the
			// first sequence item: two dependency paths in one RuleEntry
			// instead of two entries.
			Ignore: dotsnyk.RuleSet{vulnHawk: {
				{
					"request > hawk": {
						Reason:  ptr("no patch available"),
						Expires: ptr(expired2016FebMilli324),
					},
					"octonode > request > hawk": {
						Reason:  ptr("None given"),
						Expires: ptr(expired2016MayMilli066),
					},
				},
				{"npm > request > hawk": {
					Reason:  ptr("no patch available"),
					Expires: ptr(expired2016FebMilli325),
				}},
			}},
		},
	}, {
		name: "with-dash",
		file: "issues/SC-1106/with-dash.snyk",
		want: dotsnyk.Policy{
			// The same content correctly dashed: three separate entries.
			Ignore: dotsnyk.RuleSet{vulnHawk: {
				{"request > hawk": {
					Reason:  ptr("no patch available"),
					Expires: ptr(expired2016FebMilli324),
				}},
				{"octonode > request > hawk": {
					Reason:  ptr("None given"),
					Expires: ptr(expired2016MayMilli066),
				}},
				{"npm > request > hawk": {
					Reason:  ptr("no patch available"),
					Expires: ptr(expired2016FebMilli325),
				}},
			}},
		},
	}, {
		name:    "old-format",
		file:    "old-snyk-config/.snyk",
		wantErr: "old, unsupported .snyk format detected",
	}, {
		name: "malformed-patch",
		file: "issues/BST-264/missing-path-to-package.snyk",
		// Diverges from lib/parser/v1.ts — see the parity table in go/README.md.
		// This parser applies the old-format check to `patch` as well as
		// `ignore`; TypeScript checks only `ignore` and silently drops the entry.
		wantErr: "old, unsupported .snyk format detected",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(repoFixtures + tc.file)
			require.NoError(t, err)

			p, err := dotsnyk.Unmarshal(bytes.NewReader(data))

			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, *p)
		})
	}
}
