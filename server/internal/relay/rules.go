package relay

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

type compiledRules struct {
	cidrs   []netip.Prefix
	domains []string
	urls    []*regexp.Regexp
}

func compileRules(config RuleConfig) (*compiledRules, error) {
	if len(config.CIDRs)+len(config.Domains)+len(config.URLRegex) > 256 {
		return nil, fmt.Errorf("too many rules")
	}
	r := new(compiledRules)
	for _, value := range config.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("invalid IPv4 CIDR")
		}
		r.cidrs = append(r.cidrs, prefix.Masked())
	}
	for _, value := range config.Domains {
		domain, err := normalizeDomain(value)
		if err != nil {
			return nil, err
		}
		r.domains = append(r.domains, domain)
	}
	for _, value := range config.URLRegex {
		if len(value) > 4096 {
			return nil, fmt.Errorf("HTTP URL regexp is too large")
		}
		pattern, err := regexp.Compile(value)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTP URL regexp")
		}
		r.urls = append(r.urls, pattern)
	}
	return r, nil
}

// HTTP evaluates the full configured OR-list. Opaque protocols use only rules
// for which an actual IPv4 address or identified domain is available.
func (r *compiledRules) allows(ip netip.Addr, host, url string, isHTTP bool) bool {
	if r == nil || len(r.cidrs)+len(r.domains)+len(r.urls) == 0 {
		return true
	}
	available := false
	if ip.Is4() && len(r.cidrs) != 0 {
		available = true
		for _, prefix := range r.cidrs {
			if prefix.Contains(ip) {
				return true
			}
		}
	}
	if domain, err := normalizeDomain(host); err == nil && len(r.domains) != 0 {
		available = true
		for _, rule := range r.domains {
			if domain == rule || strings.HasSuffix(domain, "."+rule) {
				return true
			}
		}
	}
	if isHTTP {
		if url != "" {
			for _, pattern := range r.urls {
				if pattern.MatchString(url) {
					return true
				}
			}
		}
		return false
	}
	return !available
}

func normalizeDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || strings.ContainsAny(value, "/\\:@[]*?#") {
		return "", fmt.Errorf("invalid domain")
	}
	value, err := idna.Lookup.ToASCII(value)
	value = strings.TrimSuffix(value, ".")
	if err != nil || len(value) > 253 {
		return "", fmt.Errorf("invalid domain")
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", fmt.Errorf("IP address is not a domain")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain label")
		}
		for _, c := range label {
			if c < 'a' || c > 'z' {
				if c < '0' || c > '9' {
					if c != '-' {
						return "", fmt.Errorf("invalid domain label")
					}
				}
			}
		}
	}
	return value, nil
}

func normalizeTarget(target Target) (Target, error) {
	if target.Port < 1 || target.Port > 65535 {
		return Target{}, badProtocol("invalid target port")
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(target.Host)); err == nil {
		if !ip.Is4() {
			return Target{}, badProtocol("only IPv4 targets are supported")
		}
		target.Host = ip.String()
		return target, nil
	}
	host, err := normalizeDomain(target.Host)
	if err != nil {
		return Target{}, badProtocol("invalid target host")
	}
	target.Host = host
	return target, nil
}
