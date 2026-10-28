package dotsnyk

import (
	"fmt"
	"time"
)

// Section names the part of a policy that holds a rule.
type Section string

// The sections of a policy that hold rules.
const (
	SectionIgnore = Section("ignore")
	SectionPatch  = Section("patch")
)

// Warning reports a rule that Unmarshal could not read in full, or read with a
// meaning other than the one its text states. The rest of the policy is
// unaffected. A Warning is a *SkippedRule, a *DroppedField or a
// *NonStandardExpiry.
type Warning interface {
	fmt.Stringer
	warning()
}

// SkippedRule reports a rule entry left out of the policy because a value that
// decides what it matches or when it expires could not be read. Path is empty
// when the entry has no readable dependency path.
type SkippedRule struct {
	Section Section
	VulnID  VulnID
	Path    string
	Line    int
	Reason  string
}

func (w *SkippedRule) String() string {
	if w.Path == "" {
		return fmt.Sprintf("line %d: skipped %s rule for %s: %s", w.Line, w.Section, w.VulnID, w.Reason)
	}
	return fmt.Sprintf("line %d: skipped %s rule for %s at '%s': %s", w.Line, w.Section, w.VulnID, w.Path, w.Reason)
}

func (*SkippedRule) warning() {}

// DroppedField reports a rule kept without one of its descriptive fields, such
// as reason or ignoredBy, which do not change what the rule matches.
type DroppedField struct {
	Section Section
	VulnID  VulnID
	Path    string
	Field   string
	Line    int
	Reason  string
}

func (w *DroppedField) String() string {
	return fmt.Sprintf("line %d: dropped %s from %s rule for %s at '%s': %s",
		w.Line, w.Field, w.Section, w.VulnID, w.Path, w.Reason)
}

func (*DroppedField) warning() {}

// NonStandardExpiry reports a rule kept with an expiry other than the time its
// expires states, or with an expires that is not a valid timestamp. Expires is
// when the TypeScript implementation stops applying the rule for that value, or
// nil when it never does.
type NonStandardExpiry struct {
	Section Section
	VulnID  VulnID
	Path    string
	Line    int
	Value   string
	Expires *time.Time
}

func (w *NonStandardExpiry) String() string {
	outcome := "never expires"
	if w.Expires != nil {
		outcome = "expires at " + w.Expires.Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("line %d: %s rule for %s at '%s' %s: expires: '%s' is read as the TypeScript implementation reads it",
		w.Line, w.Section, w.VulnID, w.Path, outcome, w.Value)
}

func (*NonStandardExpiry) warning() {}
