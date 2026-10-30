package dotsnyk

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// UnmarshalYAML decodes a Policy, rejecting a document that is not a mapping. A
// rule it cannot read in full is reported in Warnings rather than failing the
// whole policy.
func (p *Policy) UnmarshalYAML(node *yaml.Node) error {
	return p.decode(node, nil)
}

type sourcedPolicy struct {
	policy *Policy
	lines  []string
}

func (s *sourcedPolicy) UnmarshalYAML(node *yaml.Node) error {
	return s.policy.decode(node, s.lines)
}

func (p *Policy) decode(node *yaml.Node, lines []string) error {
	if node.Kind != yaml.MappingNode {
		if isNullNode(node) {
			return nil
		}
		return notAPolicy(node)
	}

	var shadow struct {
		Version string               `yaml:"version"`
		Ignore  yaml.Node            `yaml:"ignore"`
		Patch   yaml.Node            `yaml:"patch"`
		Exclude *map[string]any      `yaml:"exclude,omitempty"`
		Other   map[string]yaml.Node `yaml:",inline"`
	}
	if err := node.Decode(&shadow); err != nil {
		return err //nolint:wrapcheck // Unmarshal adds the user-facing prefix.
	}

	decoded := Policy{
		Version: shadow.Version,
		Exclude: shadow.Exclude,
	}
	d := policyDecoder{lines: lines}
	if err := d.ruleSet(SectionIgnore, &shadow.Ignore, &decoded.Ignore); err != nil {
		return err
	}
	if err := d.ruleSet(SectionPatch, &shadow.Patch, &decoded.Patch); err != nil {
		return err
	}
	threshold, err := d.failThreshold(shadow.Other)
	if err != nil {
		return err
	}
	if threshold != "" {
		decoded.FailThreshold = &threshold
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
	lines    []string
	expiries map[expiryKey]expiry
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

var failThresholdKeys = []string{
	"failThreshold",
	"fail_threshold",
	"failthreshold",
	"threshold",
	"fail_threshhold", //nolint:misspell // A typo the TypeScript parser accepts.
}

func (d *policyDecoder) failThreshold(fields map[string]yaml.Node) (Severity, error) {
	for _, key := range failThresholdKeys {
		field, ok := fields[key]
		if !ok {
			continue
		}
		value := resolveAlias(&field)
		if truthy, _ := d.jsYAMLTruthy(value); !truthy {
			continue
		}
		if !d.isJSYAMLString(value) {
			return "", nil
		}
		return parseFailThreshold(value.Value, field.Line)
	}
	return "", nil
}

func (d *policyDecoder) isJSYAMLString(node *yaml.Node) bool {
	if node.Kind != yaml.ScalarNode {
		return false
	}
	if d.hasNonSpecificTag(node) {
		return true
	}
	tag, reason := jsYAMLNodeTag(node)
	return reason == "" && tag == tagStr
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
		var list entryList
		if nodes != nil {
			list.kept = make([]RuleEntry, 0, len(nodes))
		}
		for _, n := range nodes {
			if n.node == nil {
				list.kept = append(list.kept, nil)
				continue
			}
			if err := d.appendEntry(&list, section, vulnID, n.node); err != nil {
				return err
			}
		}
		list.kept = append(list.kept, list.moved...)
		if len(nodes) > 0 && len(list.kept) == 0 {
			continue
		}
		rules[vulnID] = list.kept
	}

	*dst = rules
	return nil
}

// entryList holds a vulnerability's entries split as snyk-policy splits them:
// the first path of each list item keeps the item's place, and the others are
// moved after every item.
type entryList struct {
	kept, moved []RuleEntry
}

func (d *policyDecoder) appendEntry(list *entryList, section Section, vulnID VulnID, node *yaml.Node) error {
	if isNullNode(node) {
		list.kept = append(list.kept, nil)
		return nil
	}

	skip := func(path string, at *yaml.Node, reason string) {
		d.warn(at, &SkippedRule{Section: section, VulnID: vulnID, Path: path, Line: at.Line, Reason: reason})
	}

	if node.Kind != yaml.MappingNode {
		skip("", node, "entry must be a mapping of dependency paths, got "+describeNode(node))
		return nil
	}
	if len(node.Content) == 0 {
		list.kept = append(list.kept, RuleEntry{})
		return nil
	}

	paths, err := d.pathNodes(section, vulnID, skip, node)
	if err != nil {
		return err
	}

	for i, p := range paths {
		if p.body == nil {
			continue
		}

		entry := RuleEntry{}
		switch {
		case isNullNode(p.body):
			entry[p.path] = &Rule{}
		case p.body.Kind == yaml.SequenceNode:
			d.warn(p.body, &NonStandardPath{
				Section: section, VulnID: vulnID, Path: p.path, Line: p.body.Line,
				Reason: "dependency path maps to a sequence, so it applies with no settings",
			})
			entry[p.path] = &Rule{}
		case p.body.Kind != yaml.MappingNode:
			skip(p.path, p.body, fmt.Sprintf(
				"dependency path must map to a set of ignore settings, but it is %s; check the indentation", describeNode(p.body)))
			continue
		default:
			if err := d.addRule(entry, section, vulnID, p.path, p.body); err != nil {
				return err
			}
		}
		if len(entry) == 0 {
			continue
		}

		if i == 0 {
			list.kept = append(list.kept, entry)
		} else {
			list.moved = append(list.moved, entry)
		}
	}
	return nil
}

type pathNode struct {
	path string
	body *yaml.Node
}

// pathNodes lists an entry's dependency paths in the order a JavaScript object
// gives its keys, which decides the path snyk-policy keeps in place. A path
// whose key is not a string is listed with no body.
func (d *policyDecoder) pathNodes(section Section, vulnID VulnID, skip func(string, *yaml.Node, string), node *yaml.Node) ([]pathNode, error) {
	paths := make([]pathNode, 0, len(node.Content)/2)
	seen := make(map[string]*yaml.Node, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode := node.Content[i]

		var path string
		switch key := resolveAlias(keyNode); key.Kind {
		case yaml.MappingNode, yaml.SequenceNode:
			var err error
			if path, err = textPath(key, keyNode.Line); err != nil {
				return nil, err
			}
			d.warn(keyNode, &NonStandardPath{
				Section: section, VulnID: vulnID, Path: path, Line: keyNode.Line,
				Reason: "dependency path is " + describeNode(key) + ", so it is read as text",
			})
		default:
			if err := keyNode.Decode(&path); err != nil {
				skip("", keyNode, "dependency path must be a string, got "+describeNode(keyNode))
				paths = append(paths, pathNode{})
				continue
			}
		}
		if first, ok := seen[path]; ok {
			return nil, fmt.Errorf("line %d: mapping key %q already defined at line %d", keyNode.Line, path, first.Line)
		}
		seen[path] = keyNode
		paths = append(paths, pathNode{path: path, body: resolveAlias(node.Content[i+1])})
	}

	slices.SortStableFunc(paths, func(a, b pathNode) int {
		ai, aIndex := arrayIndex(a)
		bi, bIndex := arrayIndex(b)
		switch {
		case aIndex && bIndex:
			return cmp.Compare(ai, bi)
		case aIndex:
			return -1
		case bIndex:
			return 1
		default:
			return 0
		}
	})
	return paths, nil
}

func arrayIndex(p pathNode) (uint64, bool) {
	if p.body == nil {
		return 0, false
	}
	n, err := strconv.ParseUint(p.path, 10, 32)
	if err != nil || n == math.MaxUint32 || strconv.FormatUint(n, 10) != p.path {
		return 0, false
	}
	return n, true
}

func textPath(key *yaml.Node, line int) (string, error) {
	if key.Kind == yaml.MappingNode {
		return "[object Object]", nil
	}
	parts := make([]string, len(key.Content))
	for i, item := range key.Content {
		switch item = resolveAlias(item); {
		case item.Kind == yaml.SequenceNode:
			return "", fmt.Errorf("line %d: nested sequences are not supported inside a dependency path", line)
		case item.Kind == yaml.MappingNode:
			parts[i] = "[object Object]"
		case !isNullNode(item):
			parts[i] = item.Value
		}
	}
	return strings.Join(parts, ","), nil
}

func (d *policyDecoder) addRule(entry RuleEntry, section Section, vulnID VulnID, path string, body *yaml.Node) error {
	var values map[string]yaml.Node
	if err := body.Decode(&values); err != nil {
		return err //nolint:wrapcheck // Unmarshal adds the user-facing prefix.
	}

	rule := &Rule{}
	if value, ok := values["expires"]; ok {
		e := d.expiry(resolveAlias(&value))
		if e.reason != "" {
			d.warn(&value, &SkippedRule{Section: section, VulnID: vulnID, Path: path, Line: value.Line, Reason: "expires: " + e.reason})
			return nil
		}
		rule.Expires = copyTime(e.at)
		if e.nonStandard {
			d.warn(&value, &NonStandardExpiry{
				Section: section, VulnID: vulnID, Path: path, Line: value.Line, Value: resolveAlias(&value).Value, Expires: copyTime(e.at),
			})
		}
	}
	if value, ok := values["disregardIfFixable"]; ok {
		var reason string
		rule.DisregardIfFixable, reason = d.disregardIfFixable(resolveAlias(&value))
		if reason != "" {
			d.warn(&value, &CoercedField{
				Section: section, VulnID: vulnID, Path: path, Field: "disregardIfFixable", Line: value.Line, Reason: reason,
			})
		}
	}
	for _, field := range ruleFields {
		value, ok := values[field.name]
		if !ok {
			continue
		}
		reason := field.decode(rule, resolveAlias(&value))
		if reason == "" {
			continue
		}
		d.warn(&value, &DroppedField{Section: section, VulnID: vulnID, Path: path, Field: field.name, Line: value.Line, Reason: reason})
	}
	entry[path] = rule
	return nil
}

type ruleField struct {
	name   string
	decode func(*Rule, *yaml.Node) string
}

var ruleFields = []ruleField{
	{name: "created", decode: func(r *Rule, n *yaml.Node) string { return decodeTime(n, &r.Created) }},
	{name: "patched", decode: func(r *Rule, n *yaml.Node) string { return decodeTime(n, &r.Patched) }},
	{name: "ignoredBy", decode: func(r *Rule, n *yaml.Node) string { return decodeValue(n, &r.IgnoredBy) }},
	{name: "reason", decode: func(r *Rule, n *yaml.Node) string { return decodeValue(n, &r.Reason) }},
	{name: "reasonType", decode: func(r *Rule, n *yaml.Node) string { return decodeValue(n, &r.ReasonType) }},
	{name: "source", decode: func(r *Rule, n *yaml.Node) string { return decodeValue(n, &r.Source) }},
	{name: "from", decode: func(r *Rule, n *yaml.Node) string { return decodeValue(n, &r.From) }},
}

func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
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
	parsed, ok := lenientTimestamp(node.Value)
	if !ok {
		return fmt.Sprintf("'%s' is not a valid timestamp", node.Value)
	}
	*dst = &parsed
	return ""
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
