package relay

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRuleAvailabilityAndDomainBoundary(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.7")
	for _, tt := range []struct {
		name       string
		config     RuleConfig
		host, url  string
		http, want bool
	}{
		{"empty", RuleConfig{}, "", "", true, true},
		{"domain boundary", RuleConfig{Domains: []string{"example.com"}}, "notexample.com", "", false, false},
		{"subdomain", RuleConfig{Domains: []string{"Example.COM."}}, "deep.api.example.com", "", false, true},
		{"unknown domain defaults", RuleConfig{Domains: []string{"example.com"}}, "", "", false, true},
		{"unknown domain cidr rejects", RuleConfig{CIDRs: []string{"192.168.0.0/16"}, Domains: []string{"example.com"}}, "", "", false, false},
		{"regex tcp ignored", RuleConfig{URLRegex: []string{`^http://example.com/allowed$`}}, "other.com", "", false, true},
		{"http exact url", RuleConfig{URLRegex: []string{`^http://example.com/allowed\?b=2&a=1$`}}, "example.com", "http://example.com/allowed?b=2&a=1", true, true},
		{"http regex rejects", RuleConfig{URLRegex: []string{`/allowed$`}}, "example.com", "http://example.com/denied", true, false},
		{"options star skips regex", RuleConfig{URLRegex: []string{`.*`}}, "example.com", "", true, false},
		{"or cidr allows", RuleConfig{CIDRs: []string{"10.0.0.0/8"}, Domains: []string{"other.com"}}, "example.com", "", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := compileRules(tt.config)
			if err != nil {
				t.Fatal(err)
			}
			if got := r.allows(ip, tt.host, tt.url, tt.http); got != tt.want {
				t.Fatalf("allows = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRulesRejectInvalidSnapshot(t *testing.T) {
	for _, c := range []RuleConfig{
		{CIDRs: []string{"10.0.0.0/8", "broken"}}, {CIDRs: []string{"::/0"}},
		{Domains: []string{"example.com/path"}}, {Domains: []string{"*.example.com"}},
		{Domains: []string{"127.0.0.1."}}, {Domains: []string{"127。0。0。1"}},
		{Domains: []string{"-bad.example"}}, {Domains: []string{"a..example"}},
		{URLRegex: []string{`(?<=a)b`}}, {URLRegex: []string{`(a)\1`}},
	} {
		if _, err := compileRules(c); err == nil {
			t.Errorf("accepted invalid config %+v", c)
		}
	}
}

func TestRulesLimitUntrustedCompilationWork(t *testing.T) {
	if _, err := compileRules(RuleConfig{URLRegex: make([]string, 257)}); err == nil {
		t.Fatal("accepted unbounded rule count")
	}
	if _, err := compileRules(RuleConfig{URLRegex: []string{strings.Repeat("a", 4097)}}); err == nil {
		t.Fatal("accepted oversized regexp")
	}
}

func TestDomainAndTargetNormalization(t *testing.T) {
	got, err := normalizeDomain("  BÜCHER.Example. ")
	if err != nil || got != "xn--bcher-kva.example" {
		t.Fatalf("domain = %q, %v", got, err)
	}
	got, err = normalizeDomain("BÜCHER.Example。")
	if err != nil || got != "xn--bcher-kva.example" {
		t.Fatalf("IDNA trailing dot = %q, %v", got, err)
	}
	for _, target := range []Target{{Host: "::1", Port: 80}, {Host: "example.com:80", Port: 80}, {Host: "example.com", Port: 0}, {Host: "", Port: 80}} {
		if _, err := normalizeTarget(target); err == nil {
			t.Errorf("accepted target %+v", target)
		}
	}
	gotTarget, err := normalizeTarget(Target{Host: "EXAMPLE.COM.", Port: 8080})
	if err != nil || gotTarget != (Target{Host: "example.com", Port: 8080}) {
		t.Fatalf("target = %+v, %v", gotTarget, err)
	}
}
