package rewriter

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func aliasName(name string, gate *scrub.Gate) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return name
	}
	h := sha256.Sum256([]byte("blinder/alias/v1\x00" + gate.ContentTag([]byte(name)) + "\x00" + name))
	return "_b" + hex.EncodeToString(h[:4])
}

func aliasClassList(classList string, gate *scrub.Gate) string {
	names := strings.Fields(classList)
	if len(names) == 0 {
		return classList
	}
	aliased := make([]string, len(names))
	for i, name := range names {
		aliased[i] = aliasName(name, gate)
	}
	return strings.Join(aliased, " ")
}

func isInteractiveTag(tag string) bool {
	switch tag {
	case "button", "input", "select", "textarea", "option",
		"label", "legend", "summary", "output", "meter", "progress", "a":
		return true
	}
	return false
}

func isDescriptiveMeta(attrs []tagAttr) bool {
	for _, a := range attrs {
		if a.key == "name" || a.key == "property" {
			val := strings.ToLower(strings.TrimSpace(a.val))
			switch val {
			case "description", "keywords", "author", "abstract", "subject":
				return true
			}
			if strings.HasPrefix(val, "og:") || strings.HasPrefix(val, "twitter:") {
				return true
			}
		}
	}
	return false
}
