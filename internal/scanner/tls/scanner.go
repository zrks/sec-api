package tls

import (
	"context"
	"crypto/tls"
	"net"
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
    address := net.JoinHostPort(target.Domain, "443")
    dialer := &net.Dialer{}
    // Use a context with deadline from the provided context or default timeout.
    conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
        InsecureSkipVerify: true,
    })
    if err != nil {
        // return an observation capturing the error
        return []scanner.Observation{
            {
                Category: "tls",
                Subject:  target.Domain,
                Key:      "error",
                Value:    map[string]any{"message": err.Error()},
            },
        }, nil
    }
    defer conn.Close()
    state := conn.ConnectionState()
    if len(state.PeerCertificates) == 0 {
        return []scanner.Observation{
            {
                Category: "tls",
                Subject:  target.Domain,
                Key:      "error",
                Value:    map[string]any{"message": "no peer certificates"},
            },
        }, nil
    }
    cert := state.PeerCertificates[0]
    // Calculate days until expiration
    daysUntil := int(time.Until(cert.NotAfter).Hours() / 24)
    // Observations
    var obs []scanner.Observation
    obs = append(obs, scanner.Observation{
        Category: "tls",
        Subject:  target.Domain,
        Key:      "expiry",
        Value: map[string]any{
            "not_after": cert.NotAfter.Format(time.RFC3339),
            "days_remaining": daysUntil,
        },
    })
    obs = append(obs, scanner.Observation{
        Category: "tls",
        Subject:  target.Domain,
        Key:      "issuer",
        Value: map[string]any{
            "common_name": cert.Issuer.CommonName,
            "organization": cert.Issuer.Organization,
        },
    })
    obs = append(obs, scanner.Observation{
        Category: "tls",
        Subject:  target.Domain,
        Key:      "common_name",
        Value: map[string]any{
            "common_name": cert.Subject.CommonName,
        },
    })
    if len(cert.DNSNames) > 0 {
        obs = append(obs, scanner.Observation{
            Category: "tls",
            Subject:  target.Domain,
            Key:      "dns_names",
            Value: map[string]any{
                "names": cert.DNSNames,
            },
        })
    }
    return obs, nil
}
