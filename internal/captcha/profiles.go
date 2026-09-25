package captcha

var builtInProfiles = map[string]Provider{
	"hcaptcha": {
		Name: "hcaptcha",
		ResourceOrigins: []string{
			"https://hcaptcha.com",
			"https://js.hcaptcha.com",
			"https://newassets.hcaptcha.com",
			"https://imgs.hcaptcha.com",
		},
		OpaqueFields: []string{
			"h-captcha-response",
			"g-recaptcha-response",
		},
		CSP: []CSPRule{
			{Directive: "frame-src", Source: "https://newassets.hcaptcha.com"},
		},
	},
	"recaptcha": {
		Name: "recaptcha",
		ResourceOrigins: []string{
			"https://www.google.com",
			"https://www.gstatic.com",
			"https://www.recaptcha.net",
			"https://recaptcha.net",
			"https://enterprise.google.com",
		},
		RawURLRegexes: []string{
			`^https://www\.google\.com/recaptcha/`,
			`^https://www\.gstatic\.com/recaptcha/`,
			`^https://www\.recaptcha\.net/recaptcha/`,
			`^https://recaptcha\.net/recaptcha/`,
			`^https://enterprise\.google\.com/recaptcha/`,
		},
		OpaqueFields: []string{
			"g-recaptcha-response",
		},
		CSP: []CSPRule{
			{Directive: "frame-src", Source: "https://www.google.com"},
			{Directive: "frame-src", Source: "https://www.recaptcha.net"},
			{Directive: "frame-src", Source: "https://recaptcha.net"},
		},
	},
	"turnstile": {
		Name: "turnstile",
		ResourceOrigins: []string{
			"https://challenges.cloudflare.com",
		},
		OpaqueFields: []string{
			"cf-turnstile-response",
		},
		CSP: []CSPRule{
			{Directive: "frame-src", Source: "https://challenges.cloudflare.com"},
		},
	},
}
