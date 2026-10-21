package dotsnyk

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// UnmarshalYAML decodes a Policy, rejecting a document that is not a mapping. A
// rule it cannot read in full is reported in Warnings rather than failing the
// whole policy.
func (p *Policy) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		if isNullNode(node) {
			return nil
		}
		return notAPolicy(node)
	}

	var shadow struct {
		Version       string          `yaml:"version"`
		FailThreshold *Severity       `yaml:"failThreshold,omitempty"`
		Ignore        yaml.Node       `yaml:"ignore"`
		Patch         yaml.Node       `yaml:"patch"`
		Exclude       *map[string]any `yaml:"exclude,omitempty"`
	}
	if err := node.Decode(&shadow); err != nil {
		return err //nolint:wrapcheck // Unmarshal adds the user-facing prefix.
	}

	decoded := Policy{
		Version:       shadow.Version,
		FailThreshold: shadow.FailThreshold,
		Exclude:       shadow.Exclude,
	}
	var d policyDecoder
	if err := d.ruleSet(SectionIgnore, &shadow.Ignore, &decoded.Ignore); err != nil {
		return err
	}
	if err := d.ruleSet(SectionPatch, &shadow.Patch, &decoded.Patch); err != nil {
		return err
	}
	decoded.Warnings = d.finish()

	*p = decoded
	return nil
}

type positionedWarning struct {
	line, column int
	warning      Warning
}

type policyDecoder struct {
	warnings []positionedWarning
}

func (d *policyDecoder) warn(at *yaml.Node, w Warning) {
	d.warnings = append(d.warnings, positionedWarning{at.Line, at.Column, w})
}

func (d *policyDecoder) finish() []Warning {
	if len(d.warnings) == 0 {
		return nil
	}

	slices.SortStableFunc(d.warnings, func(a, b positionedWarning) int {
		return cmp.Or(cmp.Compare(a.line, b.line), cmp.Compare(a.column, b.column))
	})

	warnings := make([]Warning, len(d.warnings))
	for i, w := range d.warnings {
		warnings[i] = w.warning
	}
	return warnings
}

func (d *policyDecoder) ruleSet(section Section, node *yaml.Node, dst *RuleSet) error {
	node = resolveAlias(node)
	switch node.Kind {
	case 0:
		return nil
	case yaml.MappingNode:
		return d.ruleMapping(section, node, dst)
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			*dst = RuleSet{}
			return nil
		}
		return fmt.Errorf("line %d: rule set must be a mapping, got a non-empty sequence", node.Line)
	case yaml.ScalarNode:
		if node.Tag == tagNull {
			return nil
		}
		if node.Value == "" {
			*dst = RuleSet{}
			return nil
		}
		return fmt.Errorf("line %d: rule set must be a mapping, got scalar %q", node.Line, node.Value)
	default:
		return fmt.Errorf("line %d: rule set has unsupported YAML kind %d", node.Line, node.Kind)
	}
}

const tagMerge = "!!merge"

type entryNode struct {
	node *yaml.Node
}

func (e *entryNode) UnmarshalYAML(node *yaml.Node) error {
	e.node = node
	return nil
}

func (d *policyDecoder) ruleMapping(section Section, node *yaml.Node, dst *RuleSet) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.ShortTag() != tagMerge && resolveAlias(value).Kind == yaml.MappingNode {
			return &PolicyError{msg: "old, unsupported .snyk format detected"}
		}
	}

	var entryNodes map[VulnID][]entryNode
	if err := node.Decode(&entryNodes); err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}

	rules := make(RuleSet, len(entryNodes))
	for _, vulnID := range slices.Sorted(maps.Keys(entryNodes)) {
		nodes := entryNodes[vulnID]
		var entries []RuleEntry
		if nodes != nil {
			entries = make([]RuleEntry, 0, len(nodes))
		}
		for _, n := range nodes {
			if n.node == nil {
				entries = append(entries, nil)
				continue
			}
			var err error
			if entries, err = d.appendEntry(entries, section, vulnID, n.node); err != nil {
				return err
			}
		}
		if len(nodes) > 0 && len(entries) == 0 {
			continue
		}
		rules[vulnID] = entries
	}

	*dst = rules
	return nil
}

func (d *policyDecoder) appendEntry(entries []RuleEntry, section Section, vulnID VulnID, node *yaml.Node) ([]RuleEntry, error) {
	if isNullNode(node) {
		return append(entries, nil), nil
	}

	kept := len(d.warnings)
	skip := func(path string, at *yaml.Node, reason string) ([]RuleEntry, error) {
		d.warnings = d.warnings[:kept]
		d.warn(at, &SkippedRule{Section: section, VulnID: vulnID, Path: path, Line: at.Line, Reason: reason})
		return entries, nil
	}

	if node.Kind != yaml.MappingNode {
		return skip("", node, "entry must be a mapping of dependency paths, got "+describeNode(node))
	}

	entry := make(RuleEntry, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode, body := node.Content[i], resolveAlias(node.Content[i+1])

		var path string
		if err := keyNode.Decode(&path); err != nil {
			return skip("", keyNode, "dependency path must be a string, got "+describeNode(keyNode))
		}
		if isNullNode(body) {
			entry[path] = &Rule{}
			continue
		}
		if body.Kind != yaml.MappingNode {
			return skip(path, body, fmt.Sprintf(
				"dependency path must map to a set of ignore settings, but it is %s; check the indentation", describeNode(body)))
		}

		if err := d.addRule(entry, section, vulnID, path, body); err != nil {
			return nil, err
		}
	}

	if len(entry) == 0 && len(node.Content) > 0 {
		return entries, nil
	}
	return append(entries, entry), nil
}

func (d *policyDecoder) addRule(entry RuleEntry, section Section, vulnID VulnID, path string, body *yaml.Node) error {
	var values map[string]yaml.Node
	if err := body.Decode(&values); err != nil {
		return err //nolint:wrapcheck // Unmarshal adds the user-facing prefix.
	}

	kept := len(d.warnings)
	rule := &Rule{}
	for _, field := range ruleFields {
		value, ok := values[field.name]
		if !ok {
			continue
		}
		reason := field.decode(rule, resolveAlias(&value))
		if reason == "" {
			continue
		}
		if field.skipsRule {
			d.warnings = d.warnings[:kept]
			d.warn(&value, &SkippedRule{Section: section, VulnID: vulnID, Path: path, Line: value.Line, Reason: field.name + ": " + reason})
			return nil
		}
		d.warn(&value, &DroppedField{Section: section, VulnID: vulnID, Path: path, Field: field.name, Line: value.Line, Reason: reason})
	}
	entry[path] = rule
	return nil
}

type ruleField struct {
	name      string
	skipsRule bool
	decode    func(*Rule, *yaml.Node) string
}

var ruleFields = []ruleField{
	{name: "created", decode: func(r *Rule, n *yaml.Node) string { return decodeTime(n, &r.Created) }},
	{name: "expires", skipsRule: true, decode: func(r *Rule, n *yaml.Node) string { return decodeTime(n, &r.Expires) }},
	{name: "patched", decode: func(r *Rule, n *yaml.Node) string { return decodeTime(n, &r.Patched) }},
	{name: "ignoredBy", decode: func(r *Rule, n *yaml.Node) string { return decodeValue(n, &r.IgnoredBy) }},
	{name: "reason", decode: func(r *Rule, n *yaml.Node) string { return decodeValue(n, &r.Reason) }},
	{name: "reasonType", decode: func(r *Rule, n *yaml.Node) string { return decodeValue(n, &r.ReasonType) }},
	{name: "source", decode: func(r *Rule, n *yaml.Node) string { return decodeValue(n, &r.Source) }},
	{name: "from", decode: func(r *Rule, n *yaml.Node) string { return decodeValue(n, &r.From) }},
	{name: "disregardIfFixable", skipsRule: true, decode: func(r *Rule, n *yaml.Node) string {
		return decodeValue(n, &r.DisregardIfFixable)
	}},
}

func decodeTime(node *yaml.Node, dst **time.Time) string {
	if isNullNode(node) {
		return ""
	}
	if node.Kind != yaml.ScalarNode {
		return "must be a timestamp, got " + describeNode(node)
	}
	if node.Tag == tagNull {
		return fmt.Sprintf("'%s' is tagged !!null", node.Value)
	}
	for _, layout := range lenientTimeFormats {
		if parsed, err := time.Parse(layout, node.Value); err == nil {
			*dst = &parsed
			return ""
		}
	}
	return fmt.Sprintf("'%s' is not a valid timestamp", node.Value)
}

func decodeValue[T any](node *yaml.Node, dst **T) string {
	var value *T
	if err := node.Decode(&value); err != nil {
		return typeErrorReason(err)
	}
	*dst = value
	return ""
}

func typeErrorReason(err error) string {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return strings.TrimPrefix(err.Error(), "yaml: ")
	}

	reasons := make([]string, 0, len(typeErr.Errors))
	for _, msg := range typeErr.Errors {
		if _, rest, ok := strings.Cut(msg, ": "); ok && strings.HasPrefix(msg, "line ") {
			msg = rest
		}
		reasons = append(reasons, sanitizeTypeError(msg))
	}
	return strings.Join(reasons, "; ")
}

func resolveAlias(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.AliasNode {
		return node.Alias
	}
	return node
}
