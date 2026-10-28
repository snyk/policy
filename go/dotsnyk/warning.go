package dotsnyk

import "fmt"

// Section names the part of a policy that holds a rule.
type Section string

// The sections of a policy that hold rules.
const (
	SectionIgnore = Section("ignore")
	SectionPatch  = Section("patch")
)

// Warning reports a rule that Unmarshal could not read in full. The rest of the
// policy is unaffected. A Warning is a *SkippedRule, a *DroppedField or a
// *NonStandardPath.
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

// NonStandardPath reports a dependency path that is not written as a rule
// expects but is kept the way the TypeScript implementation reads it, such as
// a path that maps to a sequence or a path key that is not a string.
type NonStandardPath struct {
	Section Section
	VulnID  VulnID
	Path    string
	Line    int
	Reason  string
}

func (w *NonStandardPath) String() string {
	return fmt.Sprintf("line %d: %s rule for %s at '%s' is read as the TypeScript implementation reads it: %s",
		w.Line, w.Section, w.VulnID, w.Path, w.Reason)
}

func (*NonStandardPath) warning() {}
