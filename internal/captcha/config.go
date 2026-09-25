package captcha

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type SubmissionRule struct {
	Target    string         `yaml:"target"`
	Method    string         `yaml:"method"`
	RawRegex  string         `yaml:"path_regex"`
	PathRegex *regexp.Regexp `yaml:"-"`
}

type CSPRule struct {
	Directive string `yaml:"directive"`
	Source    string `yaml:"source"`
}

type Provider struct {
	Name            string           `yaml:"name"`
	ResourceOrigins []string         `yaml:"resource_origins"`
	RawURLRegexes   []string         `yaml:"resource_url_regex"`
	URLRegexes      []*regexp.Regexp `yaml:"-"`
	OpaqueFields    []string         `yaml:"opaque_fields"`
	Submissions     []SubmissionRule `yaml:"submissions"`
	CSP             []CSPRule        `yaml:"-"`
	TorPolicy       string           `yaml:"tor_policy"`
}

const (
	TorPolicyRouteWithTarget = "route-with-target"
	TorPolicyDirect          = "direct"
)

type Config struct {
	Providers []Provider
	Matcher   *Matcher
}

type rawConfig struct {
	Version int `yaml:"version"`
	Captcha struct {
		Providers []string   `yaml:"providers"`
		Custom    []Provider `yaml:"custom"`
	} `yaml:"captcha"`
}

func ParseConfig(data []byte) (*Config, error) {
	if len(data) == 0 {
		return &Config{}, nil
	}

	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("captcha config: %w", err)
	}

	if raw.Version != 1 {
		return nil, fmt.Errorf("captcha config: unsupported version %d", raw.Version)
	}

	names := map[string]bool{}
	var providers []Provider

	for _, name := range raw.Captcha.Providers {
		profile, ok := builtInProfiles[name]
		if !ok {
			return nil, fmt.Errorf("captcha config: unknown built-in provider %q", name)
		}
		if names[name] {
			return nil, fmt.Errorf("captcha config: duplicate provider %q", name)
		}
		names[name] = true
		compiled, err := compileProvider(profile)
		if err != nil {
			return nil, fmt.Errorf("captcha config: built-in %q: %w", name, err)
		}
		providers = append(providers, compiled)
	}

	for _, custom := range raw.Captcha.Custom {
		if custom.Name == "" {
			return nil, fmt.Errorf("captcha config: custom provider missing name")
		}
		if names[custom.Name] {
			return nil, fmt.Errorf("captcha config: duplicate provider %q", custom.Name)
		}
		if len(custom.ResourceOrigins) == 0 {
			return nil, fmt.Errorf("captcha config: provider %q has no resource_origins", custom.Name)
		}
		names[custom.Name] = true
		compiled, err := compileProvider(custom)
		if err != nil {
			return nil, fmt.Errorf("captcha config: provider %q: %w", custom.Name, err)
		}
		providers = append(providers, compiled)
	}

	cfg := &Config{Providers: providers}
	cfg.Matcher = NewMatcher(cfg)
	return cfg, nil
}

func compileProvider(p Provider) (Provider, error) {
	torPolicy := p.TorPolicy
	if torPolicy == "" {
		torPolicy = TorPolicyRouteWithTarget
	}
	if torPolicy != TorPolicyRouteWithTarget && torPolicy != TorPolicyDirect {
		return Provider{}, fmt.Errorf("invalid tor_policy %q (must be %q or %q)",
			torPolicy, TorPolicyRouteWithTarget, TorPolicyDirect)
	}

	result := Provider{
		Name:            p.Name,
		ResourceOrigins: make([]string, len(p.ResourceOrigins)),
		OpaqueFields:    make([]string, len(p.OpaqueFields)),
		CSP:             make([]CSPRule, len(p.CSP)),
		TorPolicy:       torPolicy,
	}
	copy(result.ResourceOrigins, p.ResourceOrigins)
	copy(result.OpaqueFields, p.OpaqueFields)
	copy(result.CSP, p.CSP)

	for _, origin := range result.ResourceOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			return Provider{}, fmt.Errorf("invalid resource origin %q", origin)
		}
	}

	for _, raw := range p.RawURLRegexes {
		re, err := regexp.Compile(raw)
		if err != nil {
			return Provider{}, fmt.Errorf("invalid resource_url_regex %q: %w", raw, err)
		}
		result.URLRegexes = append(result.URLRegexes, re)
	}
	result.RawURLRegexes = make([]string, len(p.RawURLRegexes))
	copy(result.RawURLRegexes, p.RawURLRegexes)

	for i, sub := range p.Submissions {
		compiled := SubmissionRule{
			Target:   sub.Target,
			Method:   sub.Method,
			RawRegex: sub.RawRegex,
		}
		if sub.RawRegex != "" {
			re, err := regexp.Compile(sub.RawRegex)
			if err != nil {
				return Provider{}, fmt.Errorf("invalid submission path_regex %q: %w", sub.RawRegex, err)
			}
			compiled.PathRegex = re
		}
		if i < len(result.Submissions) {
			result.Submissions[i] = compiled
		} else {
			result.Submissions = append(result.Submissions, compiled)
		}
	}
	if len(result.Submissions) == 0 && len(p.Submissions) > 0 {
		result.Submissions = make([]SubmissionRule, 0, len(p.Submissions))
		for _, sub := range p.Submissions {
			compiled := SubmissionRule{
				Target:   sub.Target,
				Method:   sub.Method,
				RawRegex: sub.RawRegex,
			}
			if sub.RawRegex != "" {
				re, err := regexp.Compile(sub.RawRegex)
				if err != nil {
					return Provider{}, fmt.Errorf("invalid submission path_regex %q: %w", sub.RawRegex, err)
				}
				compiled.PathRegex = re
			}
			result.Submissions = append(result.Submissions, compiled)
		}
	}

	return result, nil
}

type Matcher struct {
	providers    []Provider
	opaqueFields map[string][]Provider
	originHosts  map[string][]Provider
	primaryHost  string
}

func NewMatcher(cfg *Config) *Matcher {
	m := &Matcher{
		providers:    cfg.Providers,
		opaqueFields: make(map[string][]Provider),
		originHosts:  make(map[string][]Provider),
	}

	for _, p := range cfg.Providers {
		for _, field := range p.OpaqueFields {
			m.opaqueFields[field] = append(m.opaqueFields[field], p)
		}
		for _, origin := range p.ResourceOrigins {
			u, _ := url.Parse(origin)
			if u != nil {
				m.originHosts[strings.ToLower(u.Hostname())] = append(m.originHosts[strings.ToLower(u.Hostname())], p)
			}
		}
	}

	return m
}

func (m *Matcher) SetPrimaryHost(host string) {
	m.primaryHost = strings.ToLower(host)
}

func (m *Matcher) Providers() []Provider {
	return m.providers
}

func (m *Matcher) ProviderNames() []string {
	names := make([]string, len(m.providers))
	for i, p := range m.providers {
		names[i] = p.Name
	}
	return names
}

func (m *Matcher) IsProviderResource(u *url.URL) bool {
	full := u.String()

	for _, p := range m.providers {
		originMatch := false
		for _, origin := range p.ResourceOrigins {
			ou, _ := url.Parse(origin)
			if ou != nil && sameOriginURL(ou, u) {
				originMatch = true
				break
			}
		}
		if !originMatch {
			continue
		}
		if len(p.URLRegexes) == 0 {
			return true
		}
		for _, re := range p.URLRegexes {
			if re.MatchString(full) {
				return true
			}
		}
	}

	return false
}

func sameOriginURL(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func (m *Matcher) IsOpaqueField(fieldName string) bool {
	_, ok := m.opaqueFields[fieldName]
	return ok
}

func (m *Matcher) SubmissionHasOpaqueFields(r *http.Request, fieldName string, upstreamHost ...string) bool {
	providers, ok := m.opaqueFields[fieldName]
	if !ok {
		return false
	}

	var reqHost string
	if len(upstreamHost) > 0 {
		reqHost = strings.ToLower(upstreamHost[0])
	}

	for _, p := range providers {
		if len(p.Submissions) == 0 {
			continue
		}
		for _, sub := range p.Submissions {
			if sub.Method != "" && !strings.EqualFold(sub.Method, r.Method) {
				continue
			}
			if sub.PathRegex != nil && !sub.PathRegex.MatchString(r.URL.Path) {
				continue
			}
			if sub.Target != "" && reqHost != "" && m.primaryHost != "" {
				if sub.Target == "primary" && reqHost != m.primaryHost {
					continue
				}
			}
			return true
		}
	}

	return len(providers) > 0 && allProvidersLackSubmissions(providers)
}

func allProvidersLackSubmissions(providers []Provider) bool {
	for _, p := range providers {
		if len(p.Submissions) > 0 {
			return false
		}
	}
	return true
}

func (m *Matcher) ShouldBypassTor(hostname string) bool {
	host := strings.ToLower(hostname)
	providers := m.originHosts[host]
	for _, p := range providers {
		if p.TorPolicy == TorPolicyDirect {
			return true
		}
	}
	return false
}

func (m *Matcher) RouteWithTargetOrigins() []string {
	var origins []string
	for _, p := range m.providers {
		if p.TorPolicy == TorPolicyRouteWithTarget {
			origins = append(origins, p.ResourceOrigins...)
		}
	}
	return origins
}

func (m *Matcher) ShouldRouteResource(u *url.URL) bool {
	// Policies apply to the complete matched resource, not every URL sharing a
	// hostname. Overlapping rules choose the more restrictive Tor route.
	for _, p := range m.providers {
		if p.TorPolicy == TorPolicyDirect {
			continue
		}
		one := Matcher{providers: []Provider{p}}
		if one.IsProviderResource(u) {
			return true
		}
	}
	return false
}

func (m *Matcher) CSPDirectives() []string {
	seen := map[string]bool{}
	var directives []string
	for _, p := range m.providers {
		for _, csp := range p.CSP {
			entry := csp.Directive + " " + csp.Source
			if !seen[entry] {
				seen[entry] = true
				directives = append(directives, entry)
			}
		}
		for _, origin := range p.ResourceOrigins {
			u, _ := url.Parse(origin)
			if u == nil {
				continue
			}
			host := u.Scheme + "://" + u.Hostname()
			entries := []string{
				"script-src " + host,
				"frame-src " + host,
				"connect-src " + host,
				"style-src " + host,
			}
			for _, e := range entries {
				if !seen[e] {
					seen[e] = true
					directives = append(directives, e)
				}
			}
		}
	}
	return directives
}
