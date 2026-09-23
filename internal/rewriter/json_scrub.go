package rewriter

import (
	"encoding/json"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func scrubJSON(body []byte, gate *scrub.Gate, context string) []byte {
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return gate.ScrubBytes(body, context)
	}
	scrubbed := scrubJSONValue(parsed, gate, context)
	out, err := json.Marshal(scrubbed)
	if err != nil {
		return gate.ScrubBytes(body, context)
	}
	return out
}

func scrubJSONValue(v interface{}, gate *scrub.Gate, context string) interface{} {
	switch val := v.(type) {
	case string:
		return gate.Scrub(val, context)
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, child := range val {
			result[k] = scrubJSONValue(child, gate, context)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, child := range val {
			result[i] = scrubJSONValue(child, gate, context)
		}
		return result
	default:
		return v
	}
}
