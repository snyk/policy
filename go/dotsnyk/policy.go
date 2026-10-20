package dotsnyk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const specVersion = "v1.25.1"

// Policy models the legacy .snyk policy.
type Policy struct {
	Version       string          `yaml:"version"`
	FailThreshold *Severity       `yaml:"failThreshold,omitempty"`
	Ignore        RuleSet         `yaml:"ignore"`
	Patch         RuleSet         `yaml:"patch"`
	Exclude       *map[string]any `yaml:"exclude,omitempty"`

	Warnings []Warning `yaml:"-"`
}

// New returns a pointer to a Policy, which will be prepopulated with a version
// and non-nil maps. This is the preferred way to create a new policy from scratch.
func New() *Policy {
	return &Policy{
		Version: specVersion,
		Ignore:  make(RuleSet),
		Patch:   make(RuleSet),
	}
}

// Unmarshal reads a policy from r. An empty document is a valid policy: it
// yields a zero-valued Policy rather than an error. A rule that cannot be read in
// full does not fail the policy: it is skipped or kept without the unreadable
// field, and reported in Policy.Warnings.
func Unmarshal(r io.Reader) (*Policy, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read snyk policy: %w", err)
	}

	var p Policy
	if len(bytes.TrimSpace(data)) == 0 {
		return &p, nil
	}

	if err := yaml.Unmarshal(data, &p); err != nil {
		if indentErr := asIndentationError(data, err); indentErr != nil {
			return nil, indentErr
		}
		return nil, asPolicyError(err)
	}
	return &p, nil
}

// Marshal writes a serialized policy to w.
func Marshal(w io.Writer, p *Policy) error {
	if err := yaml.NewEncoder(w).Encode(p); err != nil {
		return fmt.Errorf("failed to encode snyk policy: %w", err)
	}
	return nil
}

// Severity models an issues severity level.
type Severity string

const (
	//nolint:revive // Severity levels are self-explanatory.
	SeverityLow      = Severity("low")
	SeverityMedium   = Severity("medium")
	SeverityHigh     = Severity("high")
	SeverityCritical = Severity("critical")
)

// VulnID models the unique identifier of a Snyk vulnerability.
type VulnID string

// RuleSet models rules grouped by vulnerability identifiers.
type RuleSet map[VulnID][]RuleEntry

// RuleEntry models rules grouped by the dependency path.
type RuleEntry map[string]*Rule

// Rule models an actual policy rule.
type Rule struct {
	Created            *time.Time  `yaml:"created,omitempty"`
	Expires            *time.Time  `yaml:"expires,omitempty"`
	Patched            *time.Time  `yaml:"patched,omitempty"`
	IgnoredBy          *IgnoredBy  `yaml:"ignoredBy,omitempty"`
	Reason             *string     `yaml:"reason,omitempty"`
	ReasonType         *ReasonType `yaml:"reasonType,omitempty"`
	Source             *string     `yaml:"source,omitempty"`
	From               *string     `yaml:"from,omitempty"`
	DisregardIfFixable *bool       `yaml:"disregardIfFixable,omitempty"`
}

// IgnoredBy models the user who applied a project-level ignore.
type IgnoredBy struct {
	Email *string `yaml:"email,omitempty"`
	Name  *string `yaml:"name,omitempty"`
	ID    *string `yaml:"id,omitempty"`
}

// ReasonType is an enum of known categories for why a rule was applied.
type ReasonType string

const (
	// ReasonTypeNotVulnerable applies if an issue does not apply.
	ReasonTypeNotVulnerable = ReasonType("not-vulnerable")
	// ReasonTypeWontFix applies if an issue is intentionally being ignored.
	ReasonTypeWontFix = ReasonType("wont-fix")
	// ReasonTypeTemporaryIgnore applies if an issue is being ignored temporarily.
	ReasonTypeTemporaryIgnore = ReasonType("temporary-ignore")
)

var lenientTimeFormats = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02",
}

// PolicyError is a user-facing error about the contents of a .snyk file.
type PolicyError struct {
	msg string
	err error
}

func (e *PolicyError) Error() string { return e.msg }

func (e *PolicyError) Unwrap() error { return e.err }

func asPolicyError(err error) error {
	var pe *PolicyError
	if errors.As(err, &pe) {
		return pe
	}

	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		msgs := make([]string, 0, len(typeErr.Errors))
		for _, e := range typeErr.Errors {
			msgs = append(msgs, sanitizeTypeError(e))
		}
		return &PolicyError{msg: "invalid .snyk policy: " + strings.Join(msgs, "; "), err: err}
	}

	return &PolicyError{msg: "invalid .snyk policy: " + err.Error(), err: err}
}

func notAPolicy(node *yaml.Node) error {
	return &PolicyError{
		msg: fmt.Sprintf("invalid .snyk policy: line %d: policy must be a mapping, got %s", node.Line, describeNode(node)),
		err: &PolicyError{msg: "invalid .snyk policy: invalid yaml file"},
	}
}

// describeNode names what was found at a node, for error messages.
func describeNode(node *yaml.Node) string {
	switch node.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a sequence"
	case yaml.ScalarNode:
		return fmt.Sprintf("scalar %q", node.Value)
	default:
		return fmt.Sprintf("YAML kind %d", node.Kind)
	}
}

// sanitizeTypeError drops the Go type that yaml.v3 appends to a decoding
// failure, keeping plain types such as `bool`.
func sanitizeTypeError(msg string) string {
	idx := strings.Index(msg, " into ")
	if idx == -1 {
		return msg
	}

	target := msg[idx+len(" into "):]
	if strings.Contains(target, "struct {") || strings.Contains(target, "dotsnyk.") {
		return msg[:idx]
	}
	return msg
}

// asIndentationError describes a tab-indentation failure in our own words,
// naming the first offending line. It returns nil for any other failure.
func asIndentationError(data []byte, err error) error {
	if !isTabIndentError(err) {
		return nil
	}
	line, ok := firstTabIndentedLine(data)
	if !ok {
		return nil
	}
	return &PolicyError{
		msg: fmt.Sprintf("invalid .snyk policy: line %d: invalid indentation", line),
		err: err,
	}
}

// isTabIndentError reports whether yaml.v3 failed in one of the two ways it
// signals a tab used as indentation.
func isTabIndentError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "found character that cannot start any token") ||
		strings.Contains(msg, "found a tab character that violates indentation")
}

// firstTabIndentedLine returns the 1-based number of the first line whose
// indentation contains a tab.
func firstTabIndentedLine(data []byte) (int, bool) {
	for i, line := range bytes.Split(data, []byte("\n")) {
		indent := line[:len(line)-len(bytes.TrimLeft(line, " \t"))]
		if bytes.IndexByte(indent, '\t') >= 0 {
			return i + 1, true
		}
	}
	return 0, false
}

const tagNull = "!!null"

func isNullNode(node *yaml.Node) bool {
	if node.Kind != yaml.ScalarNode {
		return false
	}
	if node.Tag == tagNull {
		return slices.Contains(nullValues, node.Value)
	}
	return node.Value == ""
}

var nullValues = []string{"", "~", "null", "Null", "NULL"}
