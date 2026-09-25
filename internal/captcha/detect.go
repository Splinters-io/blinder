package captcha

import (
	"bytes"
	"strings"
)

type DetectResult struct {
	IsCaptcha    bool
	ProviderName string
	FormAction   string
	FormMethod   string
	FormFields   map[string]string
}

var challengeIndicators = [][]byte{
	[]byte("challenge"),
	[]byte("captcha-required"),
	[]byte("please verify"),
	[]byte("verify you are human"),
	[]byte("just a moment"),
	[]byte("checking your browser"),
	[]byte("one more step"),
	[]byte("access denied"),
	[]byte("blocked"),
}

var captchaSignatures = []struct {
	provider string
	markers  [][]byte
}{
	{
		provider: "hcaptcha",
		markers: [][]byte{
			[]byte("hcaptcha.com"),
			[]byte("h-captcha"),
		},
	},
	{
		provider: "recaptcha",
		markers: [][]byte{
			[]byte("google.com/recaptcha"),
			[]byte("g-recaptcha"),
		},
	},
	{
		provider: "turnstile",
		markers: [][]byte{
			[]byte("challenges.cloudflare.com/turnstile"),
			[]byte("cf-turnstile"),
		},
	},
}

func (m *Matcher) DetectChallenge(body []byte, contentType string, statusCode int) DetectResult {
	if m == nil {
		return DetectResult{}
	}

	normCT := strings.ToLower(contentType)
	if !strings.Contains(normCT, "text/html") {
		return DetectResult{}
	}

	if statusCode >= 200 && statusCode < 300 {
		return DetectResult{}
	}

	lower := bytes.ToLower(body)

	if !hasChallengeTone(lower) {
		return DetectResult{}
	}

	for _, p := range m.providers {
		matched := false
		for _, sig := range captchaSignatures {
			if sig.provider != p.Name {
				continue
			}
			for _, marker := range sig.markers {
				if bytes.Contains(lower, marker) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}

		if !matched {
			for _, origin := range p.ResourceOrigins {
				originLower := strings.ToLower(origin)
				host := strings.TrimPrefix(strings.TrimPrefix(originLower, "https://"), "http://")
				if bytes.Contains(lower, []byte(host)) {
					matched = true
					break
				}
			}
		}

		if matched {
			action, method, fields := extractFormMetadata(body)
			return DetectResult{
				IsCaptcha:    true,
				ProviderName: p.Name,
				FormAction:   action,
				FormMethod:   method,
				FormFields:   fields,
			}
		}
	}

	return DetectResult{}
}

func extractFormMetadata(body []byte) (action, method string, fields map[string]string) {
	lower := bytes.ToLower(body)
	idx := bytes.Index(lower, []byte("<form"))
	if idx < 0 {
		return "", "", nil
	}
	end := bytes.IndexByte(lower[idx:], '>')
	if end < 0 {
		return "", "", nil
	}
	tag := string(body[idx : idx+end+1])
	action = extractAttrValue(tag, "action")
	method = strings.ToUpper(extractAttrValue(tag, "method"))
	if method == "" {
		method = "GET"
	}

	formEnd := bytes.Index(lower[idx:], []byte("</form"))
	var formBody []byte
	if formEnd >= 0 {
		formBody = body[idx : idx+formEnd]
	} else {
		formBody = body[idx:]
	}

	fields = extractHiddenInputs(formBody)
	return action, method, fields
}

func extractHiddenInputs(formBody []byte) map[string]string {
	lower := bytes.ToLower(formBody)
	fields := make(map[string]string)
	offset := 0
	for {
		idx := bytes.Index(lower[offset:], []byte("<input"))
		if idx < 0 {
			break
		}
		idx += offset
		end := bytes.IndexByte(lower[idx:], '>')
		if end < 0 {
			break
		}
		tag := string(formBody[idx : idx+end+1])
		offset = idx + end + 1

		inputType := strings.ToLower(extractAttrValue(tag, "type"))
		if inputType != "hidden" {
			continue
		}
		name := extractAttrValue(tag, "name")
		value := extractAttrValue(tag, "value")
		if name != "" {
			fields[name] = value
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func extractAttrValue(tag, attr string) string {
	lower := strings.ToLower(tag)
	needle := strings.ToLower(attr) + "="
	idx := strings.Index(lower, needle)
	if idx < 0 {
		return ""
	}
	rest := tag[idx+len(needle):]
	if len(rest) == 0 {
		return ""
	}
	if rest[0] == '"' || rest[0] == '\'' {
		quote := rest[0]
		end := strings.IndexByte(rest[1:], quote)
		if end < 0 {
			return ""
		}
		return rest[1 : 1+end]
	}
	end := strings.IndexAny(rest, " \t\n\r>")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func hasChallengeTone(lower []byte) bool {
	for _, indicator := range challengeIndicators {
		if bytes.Contains(lower, indicator) {
			return true
		}
	}
	return false
}
