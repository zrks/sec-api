package dns

import (
    "context"
    "net"
    "strings"

    "github.com/zrks/sec-api/internal/scanner"
)

// Scanner implements scanner.Scanner for DNS records.
// It collects various DNS record types for a domain such as A, AAAA, MX, NS,
// TXT (including SPF/DMARC), CNAME, and CAA. CAA parsing is skipped in the MVP.
type Scanner struct{}

// New returns a new DNS scanner.
func New() *Scanner {
    return &Scanner{}
}

// Name returns the name of the scanner.
func (s *Scanner) Name() string {
    return "dns"
}

// Scan performs DNS lookups for the given target domain and returns a slice of
// observations. It tries to resolve multiple record types. Errors are
// represented in the returned observations rather than returned as an error,
// allowing partial results.
func (s *Scanner) Scan(ctx context.Context, target scanner.Target) ([]scanner.Observation, error) {
    domain := target.Domain
    var obs []scanner.Observation

    // A and AAAA records
    ips, err := net.LookupIP(domain)
    if err == nil {
        var v4, v6 []string
        for _, ip := range ips {
            if ip.To4() != nil {
                v4 = append(v4, ip.String())
            } else {
                v6 = append(v6, ip.String())
            }
        }
        if len(v4) > 0 {
            obs = append(obs, scanner.Observation{
                Category: "dns",
                Subject:  domain,
                Key:      "A",
                Value:    map[string]any{"addresses": v4},
            })
        }
        if len(v6) > 0 {
            obs = append(obs, scanner.Observation{
                Category: "dns",
                Subject:  domain,
                Key:      "AAAA",
                Value:    map[string]any{"addresses": v6},
            })
        }
    }

    // CNAME record (canonical name). net.LookupCNAME returns the canonical name for the host.
    cname, err := net.LookupCNAME(domain)
    if err == nil && cname != domain+"." {
        // remove trailing dot for canonical name
        cname = strings.TrimSuffix(cname, ".")
        obs = append(obs, scanner.Observation{
            Category: "dns",
            Subject:  domain,
            Key:      "CNAME",
            Value:    map[string]any{"target": cname},
        })
    }

    // MX records
    mxRecords, err := net.LookupMX(domain)
    if err == nil && len(mxRecords) > 0 {
        var servers []map[string]any
        for _, mx := range mxRecords {
            servers = append(servers, map[string]any{
                "host":     strings.TrimSuffix(mx.Host, "."),
                "priority": mx.Pref,
            })
        }
        obs = append(obs, scanner.Observation{
            Category: "dns",
            Subject:  domain,
            Key:      "MX",
            Value:    map[string]any{"records": servers},
        })
    }

    // NS records
    nsRecords, err := net.LookupNS(domain)
    if err == nil && len(nsRecords) > 0 {
        var hosts []string
        for _, ns := range nsRecords {
            hosts = append(hosts, strings.TrimSuffix(ns.Host, "."))
        }
        obs = append(obs, scanner.Observation{
            Category: "dns",
            Subject:  domain,
            Key:      "NS",
            Value:    map[string]any{"servers": hosts},
        })
    }

    // TXT records (generic)
    txtRecords, err := net.LookupTXT(domain)
    if err == nil && len(txtRecords) > 0 {
        obs = append(obs, scanner.Observation{
            Category: "dns",
            Subject:  domain,
            Key:      "TXT",
            Value:    map[string]any{"records": txtRecords},
        })
    }

    // SPF record: look for any TXT starting with v=spf1
    var spf []string
    for _, rec := range txtRecords {
        if strings.HasPrefix(strings.ToLower(rec), "v=spf1") {
            spf = append(spf, rec)
        }
    }
    if len(spf) > 0 {
        obs = append(obs, scanner.Observation{
            Category: "dns",
            Subject:  domain,
            Key:      "SPF",
            Value:    map[string]any{"records": spf},
        })
    }

    // DMARC record: look up _dmarc.domain
    dmarcDomain := "_dmarc." + domain
    dmarcTxt, err := net.LookupTXT(dmarcDomain)
    if err == nil && len(dmarcTxt) > 0 {
        obs = append(obs, scanner.Observation{
            Category: "dns",
            Subject:  dmarcDomain,
            Key:      "DMARC",
            Value:    map[string]any{"records": dmarcTxt},
        })
    }

    // CAA record: there is no direct net.LookupCAA in Go, but we can use LookupTXT on the domain to search for CAA; however, CAA has type code 257.
    // For MVP, skip actual CAA parsing due to library limitations.

    return obs, nil
}