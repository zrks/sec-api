package domain

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

var blockedSuffixes = []string{".local", ".internal", ".lan", ".home", ".localhost", ".localdomain"}

// NormalizePublicDomain extracts and validates a public domain target.
func NormalizePublicDomain(input string) (string, error) {
	raw := strings.TrimSpace(strings.ToLower(input))
	if raw == "" {
		return "", fmt.Errorf("domain required")
	}
	if strings.Contains(raw, "@") {
		return "", fmt.Errorf("enter a domain, not an email address")
	}

	host := raw
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("invalid domain or URL")
		}
		host = parsed.Hostname()
	} else if strings.Contains(raw, "/") {
		parsed, err := url.Parse("https://" + raw)
		if err != nil {
			return "", fmt.Errorf("invalid domain or URL")
		}
		host = parsed.Hostname()
	}

	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if strings.HasPrefix(host, "*.") {
		return "", fmt.Errorf("wildcard domains are not supported")
	}
	if host == "localhost" {
		return "", fmt.Errorf("localhost is not a public domain")
	}
	for _, suffix := range blockedSuffixes {
		if strings.HasSuffix(host, suffix) {
			return "", fmt.Errorf("internal domains are not supported")
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
			return "", fmt.Errorf("private or internal IP targets are not supported")
		}
		return "", fmt.Errorf("enter a public domain name, not a raw IP address")
	}
	if !strings.Contains(host, ".") {
		return "", fmt.Errorf("enter a public domain name")
	}
	if strings.HasPrefix(host, "www.") {
		host = strings.TrimPrefix(host, "www.")
	}
	parts := strings.Split(host, ".")
	for _, part := range parts {
		if part == "" {
			return "", fmt.Errorf("invalid domain name")
		}
	}
	return host, nil
}
