package dotsnyk_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/policy/go/dotsnyk"
)

func TestPolicy_Unmarshal_ReadsExpiresAsTheTypeScriptPolicyDoes(t *testing.T) {
	testCases := []struct {
		expires     string
		want        *time.Time
		nonStandard string
	}{
		{expires: "2030-01-01", want: utcTime(2030, time.January, 1, 0, 0, 0, 0)},
		{expires: "'2116-03-01T14:30:04.136Z'", want: utcTime(2116, time.March, 1, 14, 30, 4, 136)},
		{expires: "'2030-01-01T10:00:00Z'", want: utcTime(2030, time.January, 1, 10, 0, 0, 0)},
		{expires: "2030-01-01T10:00:00+05:00", want: utcTime(2030, time.January, 1, 5, 0, 0, 0)},
		{expires: "'2030-01-01T10:00:00+05:00'", want: utcTime(2030, time.January, 1, 10, 0, 0, 0), nonStandard: "2030-01-01T10:00:00+05:00"},
		{expires: "'2030-01-01 10:00:00'", want: utcTime(2030, time.January, 1, 0, 0, 0, 0), nonStandard: "2030-01-01 10:00:00"},
		{expires: "0030-01-01", want: utcTime(1930, time.January, 1, 0, 0, 0, 0), nonStandard: "0030-01-01"},
		{expires: "2020-35-20", want: utcTime(2022, time.November, 20, 0, 0, 0, 0), nonStandard: "2020-35-20"},
		{expires: "'2020-35-20'", want: utcTime(2021, time.January, 1, 0, 0, 0, 0), nonStandard: "2020-35-20"},
		{expires: "!!timestamp 2030-02-30", want: utcTime(2030, time.March, 2, 0, 0, 0, 0), nonStandard: "2030-02-30"},
		{expires: "! 2030", want: utcTime(2030, time.January, 1, 0, 0, 0, 0), nonStandard: "2030"},
		{expires: "! 0", want: utcTime(0, time.January, 1, 0, 0, 0, 0), nonStandard: "0"},
		{expires: "&when ! 0", want: utcTime(0, time.January, 1, 0, 0, 0, 0), nonStandard: "0"},
		{expires: "!<!> 0", want: utcTime(0, time.January, 1, 0, 0, 0, 0), nonStandard: "0"},
		{expires: "|-\n          2030/01/01", want: utcTime(2031, time.January, 1, 0, 0, 0, 0), nonStandard: "2030/01/01"},
		{expires: "2030-02-30", want: utcTime(2030, time.March, 2, 0, 0, 0, 0), nonStandard: "2030-02-30"},
		{expires: "2030-1-5 1:02:03", want: utcTime(2030, time.January, 5, 1, 2, 3, 0), nonStandard: "2030-1-5 1:02:03"},
		{expires: "2030/01/01", want: utcTime(2031, time.January, 1, 0, 0, 0, 0), nonStandard: "2030/01/01"},
		{expires: "'2030-1-5'", want: utcTime(2030, time.October, 1, 0, 0, 0, 0), nonStandard: "2030-1-5"},
		{expires: "'2030'", want: utcTime(2030, time.January, 1, 0, 0, 0, 0), nonStandard: "2030"},
		{expires: "!!str 2030", want: utcTime(2030, time.January, 1, 0, 0, 0, 0), nonStandard: "2030"},
		{expires: "01/02/2030", want: utcTime(100, time.January, 1, 0, 0, 0, 0), nonStandard: "01/02/2030"},
		{expires: "' 2030-01-01'", want: utcTime(0, time.January, 1, 0, 0, 0, 0), nonStandard: " 2030-01-01"},
		{expires: "9999-12-31T23:59:60Z", want: utcTime(0, time.January, 1, 0, 0, 0, 0), nonStandard: "9999-12-31T23:59:60Z"},
		{expires: "never", nonStandard: "never"},
		{expires: "Jan 1 2030", nonStandard: "Jan 1 2030"},
		{expires: "2030", nonStandard: "2030"},
		{expires: "0", nonStandard: "0"},
		{expires: "true", nonStandard: "true"},
		{expires: "0x1F", nonStandard: "0x1F"},
		{expires: "017", nonStandard: "017"},
		{expires: "0b101", nonStandard: "0b101"},
		{expires: "1_000", nonStandard: "1_000"},
		{expires: "1:30", nonStandard: "1:30"},
		{expires: ".inf", nonStandard: ".inf"},
		{expires: ".nan", nonStandard: ".nan"},
		{expires: "!!float 2030", nonStandard: "2030"},
		{expires: "'9999-12-31T23:59:59.999Z'", nonStandard: "9999-12-31T23:59:59.999Z"},
		{expires: "''"},
	}

	for _, tc := range testCases {
		t.Run(tc.expires, func(t *testing.T) {
			p, err := dotsnyk.Unmarshal(strings.NewReader(policyExpiring(tc.expires)))
			require.NoError(t, err)

			rule := p.Ignore[vulnCXCT][0]["*"]
			assert.Equal(t, tc.want, inUTC(rule.Expires))
			assert.Equal(t, nonStandardExpiryWarnings(tc.nonStandard, tc.want), p.Warnings)
		})
	}
}

func TestPolicy_Unmarshal_SkipsRuleWhenExpiresTagDoesNotFitValue(t *testing.T) {
	p, err := dotsnyk.Unmarshal(strings.NewReader(policyExpiring("!!int soon")))
	require.NoError(t, err)

	assert.Empty(t, p.Ignore)
	assert.Equal(t, []dotsnyk.Warning{&dotsnyk.SkippedRule{
		Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 5,
		Reason: "expires: 'soon' is tagged !!int",
	}}, p.Warnings)
}

func TestPolicy_Unmarshal_ReadsTheSameExpiresTextDifferentlyByQuoting(t *testing.T) {
	p, err := dotsnyk.Unmarshal(strings.NewReader(`version: v1.25.0
ignore:
  SNYK-JS-CXCT-535487:
    - '*':
        expires: 2030
  SNYK-JS-LODASH-567746:
    - '*':
        expires: '2030'
`))
	require.NoError(t, err)

	assert.Nil(t, p.Ignore[vulnCXCT][0]["*"].Expires)
	assert.Equal(t, utcTime(2030, time.January, 1, 0, 0, 0, 0), p.Ignore[vulnLodash][0]["*"].Expires)
}

func TestPolicy_Unmarshal_ReadsAnAliasedExpiresLikeItsAnchor(t *testing.T) {
	p, err := dotsnyk.Unmarshal(strings.NewReader(`version: v1.25.0
ignore:
  SNYK-JS-CXCT-535487:
    - '*':
        expires: &when '2030/01/01'
  SNYK-JS-LODASH-567746:
    - '*':
        expires: *when
`))
	require.NoError(t, err)

	want := utcTime(2031, time.January, 1, 0, 0, 0, 0)
	assert.Equal(t, want, p.Ignore[vulnCXCT][0]["*"].Expires)
	assert.Equal(t, want, p.Ignore[vulnLodash][0]["*"].Expires)
}

func TestPolicy_Unmarshal_ReadsAnAliasedNonSpecificTagAsText(t *testing.T) {
	p, err := dotsnyk.Unmarshal(strings.NewReader(`version: v1.25.0
ignore:
  SNYK-JS-CXCT-535487:
    - '*':
        reason: &when ! 0
        expires: *when
`))
	require.NoError(t, err)

	assert.Equal(t, utcTime(0, time.January, 1, 0, 0, 0, 0), p.Ignore[vulnCXCT][0]["*"].Expires)
}

func TestPolicy_Unmarshal_SkipsRuleWithNonStandardExpiryAndUnreadableDisregardIfFixable(t *testing.T) {
	p, err := dotsnyk.Unmarshal(strings.NewReader(`version: v1.25.0
ignore:
  SNYK-JS-CXCT-535487:
    - '*':
        expires: never
        disregardIfFixable: maybe
`))
	require.NoError(t, err)

	assert.Empty(t, p.Ignore)
	assert.Equal(t, []dotsnyk.Warning{&dotsnyk.SkippedRule{
		Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 6,
		Reason: "disregardIfFixable: cannot unmarshal !!str `maybe` into bool",
	}}, p.Warnings)
}

func policyExpiring(expires string) string {
	return "version: v1.25.0\nignore:\n  SNYK-JS-CXCT-535487:\n    - '*':\n        expires: " + expires + "\n"
}

func nonStandardExpiryWarnings(value string, expires *time.Time) []dotsnyk.Warning {
	if value == "" {
		return nil
	}
	return []dotsnyk.Warning{&dotsnyk.NonStandardExpiry{
		Section: dotsnyk.SectionIgnore, VulnID: vulnCXCT, Path: "*", Line: 5, Value: value, Expires: expires,
	}}
}

func utcTime(year int, month time.Month, day, hour, minute, second, milli int) *time.Time {
	return ptr(time.Date(year, month, day, hour, minute, second, milli*int(time.Millisecond), time.UTC))
}

func inUTC(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	return ptr(t.UTC())
}
