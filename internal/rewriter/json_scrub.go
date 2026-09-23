package rewriter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/Splinters-io/blinder/internal/scrub"
)

func scrubJSON(body []byte, gate *scrub.Gate, context string) []byte {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var parsed interface{}
	if err := dec.Decode(&parsed); err != nil {
		return []byte("null")
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		return []byte("null")
	}
	scrubbed, err := scrubJSONValue(parsed, gate, context)
	if err != nil {
		return []byte("null")
	}
	out, err := json.Marshal(scrubbed)
	if err != nil {
		return []byte("null")
	}
	return out
}

func scrubJSONValue(v interface{}, gate *scrub.Gate, context string) (interface{}, error) {
	switch val := v.(type) {
	case string:
		return gate.Scrub(val, context), nil
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, child := range val {
			scrubbedKey := gate.Scrub(k, context)
			if _, exists := result[scrubbedKey]; exists {
				return nil, errors.New("scrubbing produced duplicate JSON keys")
			}
			scrubbed, err := scrubJSONValue(child, gate, context)
			if err != nil {
				return nil, err
			}
			result[scrubbedKey] = scrubbed
		}
		return result, nil
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, child := range val {
			var err error
			result[i], err = scrubJSONValue(child, gate, context)
			if err != nil {
				return nil, err
			}
		}
		return result, nil
	default:
		return v, nil
	}
}
