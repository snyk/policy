package dotsnyk

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const tagJSUndefined = "!!js/undefined"

var jsYAMLTrues = []string{"true", "True", "TRUE"}

func (d *policyDecoder) disregardIfFixable(node *yaml.Node) (value *bool, reason string) {
	if isNullNode(node) {
		return nil, ""
	}
	truthy, isBool := d.jsYAMLTruthy(node)
	if isBool {
		return &truthy, ""
	}
	if node.Kind != yaml.ScalarNode {
		return &truthy, fmt.Sprintf("%s is not a boolean, read as %t", describeNode(node), truthy)
	}
	return &truthy, fmt.Sprintf("%q is not a boolean, read as %t", node.Value, truthy)
}

func (d *policyDecoder) jsYAMLTruthy(node *yaml.Node) (truthy, isBool bool) {
	if node.Kind != yaml.ScalarNode {
		return true, false
	}
	tag := tagStr
	if !d.hasNonSpecificTag(node) {
		if node.Style&yaml.TaggedStyle != 0 && node.ShortTag() == tagJSUndefined {
			return false, false
		}
		var reason string
		if tag, reason = jsYAMLNodeTag(node); reason != "" {
			return true, false
		}
	}
	switch tag {
	case tagBool:
		return slices.Contains(jsYAMLTrues, node.Value), true
	case tagNull:
		return false, false
	case tagInt:
		return !jsYAMLIntIsZero(node.Value), false
	case tagFloat:
		return !jsYAMLFloatIsZero(node.Value), false
	case tagStr:
		return node.Value != "", false
	default:
		return true, false
	}
}

func jsYAMLIntIsZero(value string) bool {
	digits := strings.TrimLeft(value, "+-")
	if strings.HasPrefix(digits, "0b") || strings.HasPrefix(digits, "0x") {
		digits = digits[2:]
	}
	return strings.Trim(digits, "0_:") == ""
}

func jsYAMLFloatIsZero(value string) bool {
	body := strings.TrimLeft(strings.ToLower(strings.ReplaceAll(value, "_", "")), "+-")
	switch body {
	case ".inf":
		return false
	case ".nan":
		return true
	}
	for _, part := range strings.Split(body, ":") {
		n, err := strconv.ParseFloat(part, 64)
		if (err != nil && !errors.Is(err, strconv.ErrRange)) || n != 0 {
			return false
		}
	}
	return true
}
