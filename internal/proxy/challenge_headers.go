package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Splinters-io/blinder/internal/rewriter"
	"github.com/Splinters-io/blinder/internal/urlutil"
)

// rewriteChallengeHeaders translates browser navigation/report destinations in
// the private challenge view. Unsupported destinations fail the whole view;
// preserving an unknown URL here would let the browser bypass proxy routing.
// Policy source permissions are deliberately left to the existing CSP mapper.
func rewriteChallengeHeaders(headers http.Header, base *url.URL, mapURL func(string, *url.URL) (string, bool)) error {
	mapDestination := func(raw string) (string, error) {
		if mapped, ok := mapURL(raw, base); ok {
			return mapped, nil
		}
		return "", fmt.Errorf("unsupported challenge destination")
	}
	for name, values := range headers {
		for i, value := range values {
			var result string
			var err error
			switch strings.ToLower(name) {
			case "link", "alt-svc":
				// These can initiate browser traffic outside document navigation.
				// Their routing semantics are not modeled for isolated views yet.
				if strings.TrimSpace(value) != "" {
					return fmt.Errorf("%s: unsupported active challenge header", name)
				}
				continue
			case "location", "content-location":
				result, err = mapDestination(value)
			case "refresh":
				result, _ = urlutil.RewriteRefresh(value, func(raw string) (string, bool) {
					var mapped string
					mapped, err = mapDestination(raw)
					return mapped, err == nil
				})
			case "report-to":
				result, err = rewriteChallengeReportTo(value, mapDestination)
			case "reporting-endpoints":
				result, err = rewriteChallengeReportingEndpoints(value, mapDestination)
			case "content-security-policy", "content-security-policy-report-only":
				result = rewriter.RewriteCSPURLs(value, func(directive, source string) string {
					if directive != "report-uri" || err != nil {
						return source
					}
					var mapped string
					mapped, err = mapDestination(source)
					return mapped
				})
			default:
				continue
			}
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			values[i] = result
		}
	}
	return nil
}

// Report-To uses JSON objects, sometimes combined as an HTTP comma list. Raw
// messages retain numeric spelling and unknown fields; only endpoint URLs are
// decoded and replaced. Both the list and legacy array forms retain their shape.
func rewriteChallengeReportTo(value string, mapURL func(string) (string, error)) (string, error) {
	trimmed := strings.TrimSpace(value)
	array := strings.HasPrefix(trimmed, "[")
	input := trimmed
	if !array {
		input = "[" + trimmed + "]"
	}
	var groups []json.RawMessage
	if err := json.Unmarshal([]byte(input), &groups); err != nil {
		return "", fmt.Errorf("unsupported report configuration")
	}
	for i, raw := range groups {
		var group map[string]json.RawMessage
		if err := json.Unmarshal(raw, &group); err != nil || group == nil {
			return "", fmt.Errorf("unsupported report group")
		}
		endpointsRaw, exists := group["endpoints"]
		if !exists {
			continue
		}
		var endpoints []map[string]json.RawMessage
		if err := json.Unmarshal(endpointsRaw, &endpoints); err != nil {
			return "", fmt.Errorf("unsupported report endpoints")
		}
		for _, endpoint := range endpoints {
			var rawURL string
			// json.Unmarshal accepts null into a string as its zero value.
			// Do not repair that invalid endpoint into the document's own URL.
			if endpoint == nil || !strings.HasPrefix(strings.TrimSpace(string(endpoint["url"])), `"`) || json.Unmarshal(endpoint["url"], &rawURL) != nil {
				return "", fmt.Errorf("unsupported report endpoint URL")
			}
			mapped, err := mapURL(rawURL)
			if err != nil {
				return "", err
			}
			endpoint["url"], _ = json.Marshal(mapped)
		}
		group["endpoints"], _ = json.Marshal(endpoints)
		groups[i], _ = json.Marshal(group)
	}
	encoded, err := json.Marshal(groups)
	if err != nil {
		return "", err
	}
	if !array {
		encoded = encoded[1 : len(encoded)-1]
	}
	return string(encoded), nil
}

// Reporting-Endpoints is a Structured Fields dictionary of string URLs. Keep
// each dictionary key and parameter bytes intact. An unsupported member shape
// is rejected rather than guessed or changed into a valid endpoint definition.
func rewriteChallengeReportingEndpoints(value string, mapURL func(string) (string, error)) (string, error) {
	var out strings.Builder
	position := 0
	for position < len(value) {
		start := position
		for position < len(value) && (value[position] == ' ' || value[position] == '\t') {
			position++
		}
		keyStart := position
		if position == len(value) || !reportingKeyStart(value[position]) {
			return "", fmt.Errorf("unsupported reporting dictionary")
		}
		position++
		for position < len(value) && reportingKeyByte(value[position]) {
			position++
		}
		if position == keyStart || position >= len(value) || value[position] != '=' {
			return "", fmt.Errorf("unsupported reporting dictionary item")
		}
		position++
		stringStart := position
		rawURL, after, err := reportingString(value, position)
		if err != nil {
			return "", err
		}
		mapped, err := mapURL(rawURL)
		if err != nil {
			return "", err
		}
		for _, char := range mapped {
			if char < 0x20 || char > 0x7e {
				return "", fmt.Errorf("unsupported reporting URL encoding")
			}
		}
		out.WriteString(value[start:stringStart])
		out.WriteByte('"')
		out.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(mapped))
		out.WriteByte('"')
		position = after
		// Parameters do not contain endpoint URLs. Preserve their opaque item
		// values, recognizing quoted commas so they cannot split a dictionary.
		for position < len(value) && value[position] != ',' {
			if value[position] == '"' {
				_, end, err := reportingString(value, position)
				if err != nil {
					return "", err
				}
				position = end
				continue
			}
			if value[position] < 0x20 && value[position] != '\t' || value[position] > 0x7e || value[position] == '(' || value[position] == ')' {
				return "", fmt.Errorf("unsupported reporting parameters")
			}
			position++
		}
		out.WriteString(value[after:position])
		if position < len(value) {
			out.WriteByte(',')
			position++
			if strings.TrimSpace(value[position:]) == "" {
				return "", fmt.Errorf("unsupported reporting dictionary ending")
			}
		}
	}
	return out.String(), nil
}

func reportingKeyStart(c byte) bool { return c >= 'a' && c <= 'z' || c == '*' }
func reportingKeyByte(c byte) bool {
	return reportingKeyStart(c) || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
}

func reportingString(value string, start int) (string, int, error) {
	if start >= len(value) || value[start] != '"' {
		return "", 0, fmt.Errorf("unsupported reporting string")
	}
	var decoded strings.Builder
	for i := start + 1; i < len(value); i++ {
		c := value[i]
		if c == '"' {
			return decoded.String(), i + 1, nil
		}
		if c == '\\' {
			i++
			if i == len(value) || (value[i] != '\\' && value[i] != '"') {
				return "", 0, fmt.Errorf("unsupported reporting escape")
			}
			c = value[i]
		}
		if c < 0x20 || c > 0x7e {
			return "", 0, fmt.Errorf("unsupported reporting character")
		}
		decoded.WriteByte(c)
	}
	return "", 0, fmt.Errorf("unterminated reporting string")
}
