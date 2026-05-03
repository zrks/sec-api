package tls

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/zrks/sec-api/internal/scanner"
)

// Scanner implements scanner.Scanner for TLS certificate information.
// It connects to the target's HTTPS port and extracts certificate details such
// as expiration, issuer, and DNS names.
type Scanner struct{}

// New returns a new TLS scanner.
func New() *Scanner {
	return &Scanner{}
}

// Name returns the scanner name.
func (s *Scanner) Name() string {
	return "tls"
}

// Scan connects to the target domain on port 443 and gathers TLS certificate
// information. If the connection fails, it returns a single observation with the
// error message encoded in the value map.
func (s *Scanner) Scan(ctx context.Context, target scanner.Target) ([]scanner.Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	targets := []string{target.Domain}
	if !strings.HasPrefix(target.Domain, "www.") {
		targets = append(targets, "www."+target.Domain)
	}

	var obs []scanner.Observation
	for _, hostname := range targets {
		obs = append(obs, scanHost(ctx, hostname)...)
	}
	return obs, nil
}

func scanHost(ctx context.Context, hostname string) []scanner.Observation {
	address := net.JoinHostPort(hostname, "443")
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true, ServerName: hostname})
	if err != nil {
		return []scanner.Observation{{Category: "tls", Subject: hostname, Key: "error", Value: map[string]any{"message": err.Error()}}}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return []scanner.Observation{{Category: "tls", Subject: hostname, Key: "error", Value: map[string]any{"message": "no peer certificates"}}}
	}
	cert := state.PeerCertificates[0]
	hostnameValid := cert.VerifyHostname(hostname) == nil
	daysUntil := int(time.Until(cert.NotAfter).Hours() / 24)
	return []scanner.Observation{
		{Category: "tls", Subject: hostname, Key: "certificate", Value: map[string]any{"subject_common_name": cert.Subject.CommonName, "issuer_common_name": cert.Issuer.CommonName, "not_before": cert.NotBefore.Format(time.RFC3339), "not_after": cert.NotAfter.Format(time.RFC3339), "dns_names": cert.DNSNames, "chain_length": len(state.PeerCertificates)}},
		{Category: "tls", Subject: hostname, Key: "expiry", Value: map[string]any{"not_after": cert.NotAfter.Format(time.RFC3339), "days_remaining": daysUntil}},
		{Category: "tls", Subject: hostname, Key: "hostname_valid", Value: map[string]any{"valid": hostnameValid}},
	}
}
