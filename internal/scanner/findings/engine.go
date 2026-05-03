package findings

import (
	"sort"
	"strings"
	"time"

	"github.com/zrks/sec-api/internal/scanner"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding is a normalized issue derived from raw scan observations.
type Finding struct {
	Severity       Severity       `json:"severity"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	Recommendation string         `json:"recommendation"`
	Evidence       map[string]any `json:"evidence"`
}

// Build converts raw observations into findings for a domain.
func Build(domain string, observations []scanner.Observation) []Finding {
	var out []Finding
	var hasDMARC bool
	var dmarcWeakNone bool
	var spfFound bool
	var spfMultiple bool
	var spfWeakAll bool
	var dnsDiscovered bool
	var caaPresent bool
	var subdomainsDiscovered bool
	var hstsPresent bool
	var cspPresent bool
	var xfoPresent bool
	var xctoPresent bool
	var serverHeader string
	var httpsUnavailable bool
	var tlsExpirySeen bool
	var tlsExpired bool
	var tlsHostnameValid = true
	var tlsDaysRemaining int
	var whoisDaysRemaining int
	var whoisExpirySeen bool

	for _, observation := range observations {
		key := strings.ToLower(observation.Key)
		value, _ := observation.Value.(map[string]any)

		switch observation.Category {
		case "subdomain":
			if key == "discovered" {
				subdomainsDiscovered = true
			}
		case "dns":
			switch key {
			case "a", "aaaa", "mx", "ns", "txt", "cname":
				dnsDiscovered = true
			case "caa":
				caaPresent = true
			case "dmarc":
				hasDMARC = true
				for _, record := range stringSlice(value["records"]) {
					if strings.Contains(strings.ToLower(record), "p=none") {
						dmarcWeakNone = true
					}
				}
			case "spf_weak_all":
				spfWeakAll = true
			case "spf":
				spfFound = true
				if len(stringSlice(value["records"])) > 1 {
					spfMultiple = true
				}
				for _, record := range stringSlice(value["records"]) {
					if strings.Contains(strings.ToLower(record), "+all") {
						spfWeakAll = true
					}
				}
			}
		case "tls":
			switch key {
			case "expiry":
				tlsExpirySeen = true
				tlsDaysRemaining = intValue(value["days_remaining"])
				if notAfter, ok := value["not_after"].(string); ok {
					if parsed, err := time.Parse(time.RFC3339, notAfter); err == nil && parsed.Before(time.Now()) {
						tlsExpired = true
					}
				}
			case "hostname_valid":
				if valid, ok := value["valid"].(bool); ok {
					tlsHostnameValid = valid
				}
			}
		case "http":
			switch key {
			case "https_error", "request_error":
				httpsUnavailable = true
			case "hsts":
				hstsPresent = boolValue(value["present"])
			case "csp":
				cspPresent = boolValue(value["present"])
			case "x_frame_options":
				xfoPresent = boolValue(value["present"])
			case "x_content_type_options":
				xctoPresent = boolValue(value["present"])
			case "server_header":
				if boolValue(value["present"]) {
					serverHeader, _ = value["value"].(string)
				}
			}
		case "whois":
			switch key {
			case "expiry":
				whoisExpirySeen = true
				whoisDaysRemaining = intValue(value["days_remaining"])
			}
		}
	}

	if tlsExpired {
		out = append(out, Finding{Severity: SeverityCritical, Title: "TLS certificate expired", Description: "The TLS certificate has already expired.", Recommendation: "Renew and deploy a valid TLS certificate immediately.", Evidence: map[string]any{"domain": domain}})
	} else if tlsExpirySeen && tlsDaysRemaining <= 14 {
		out = append(out, Finding{Severity: SeverityHigh, Title: "TLS certificate expiring soon", Description: "The TLS certificate expires within 14 days.", Recommendation: "Renew the TLS certificate before it expires.", Evidence: map[string]any{"domain": domain, "days_remaining": tlsDaysRemaining}})
	} else if tlsExpirySeen && tlsDaysRemaining <= 30 {
		out = append(out, Finding{Severity: SeverityMedium, Title: "TLS certificate renewal window opened", Description: "The TLS certificate expires within 30 days.", Recommendation: "Plan and schedule certificate renewal before the expiration date.", Evidence: map[string]any{"domain": domain, "days_remaining": tlsDaysRemaining}})
	}
	if !tlsHostnameValid {
		out = append(out, Finding{Severity: SeverityCritical, Title: "TLS hostname mismatch", Description: "The TLS certificate does not match the scanned hostname.", Recommendation: "Deploy a certificate that includes the scanned hostname.", Evidence: map[string]any{"domain": domain}})
	}
	if !hasDMARC {
		out = append(out, Finding{Severity: SeverityHigh, Title: "DMARC missing", Description: "No DMARC TXT record was found.", Recommendation: "Publish a DMARC policy at _dmarc.<domain>.", Evidence: map[string]any{"domain": domain}})
	}
	if hasDMARC && dmarcWeakNone {
		out = append(out, Finding{Severity: SeverityMedium, Title: "DMARC policy is monitor-only", Description: "The DMARC policy is set to p=none, which does not enforce spoofing protection yet.", Recommendation: "Move DMARC toward quarantine or reject when your mail flows are ready.", Evidence: map[string]any{"domain": domain}})
	}
	if !spfFound {
		out = append(out, Finding{Severity: SeverityMedium, Title: "SPF missing", Description: "No SPF record was found in the domain TXT records.", Recommendation: "Publish a single SPF record for your approved outbound email services.", Evidence: map[string]any{"domain": domain}})
	}
	if spfMultiple {
		out = append(out, Finding{Severity: SeverityMedium, Title: "Multiple SPF records found", Description: "More than one SPF record was found, which can break mail authentication checks.", Recommendation: "Combine SPF values into a single SPF record.", Evidence: map[string]any{"domain": domain}})
	}
	if spfWeakAll {
		out = append(out, Finding{Severity: SeverityHigh, Title: "SPF allows +all", Description: "The SPF record contains +all, which allows spoofing from any source.", Recommendation: "Replace +all with a restrictive SPF policy such as ~all or -all.", Evidence: map[string]any{"domain": domain}})
	}
	if !caaPresent {
		out = append(out, Finding{Severity: SeverityMedium, Title: "CAA missing", Description: "No CAA records were found for the domain.", Recommendation: "Add CAA records to limit which certificate authorities may issue certificates for the domain.", Evidence: map[string]any{"domain": domain}})
	}
	if whoisExpirySeen && whoisDaysRemaining <= 30 {
		out = append(out, Finding{Severity: SeverityMedium, Title: "Domain registration expires soon", Description: "The domain registration appears to expire within 30 days.", Recommendation: "Review the registrar account and renew the domain before the expiry date.", Evidence: map[string]any{"domain": domain, "days_remaining": whoisDaysRemaining}})
	}
	if httpsUnavailable {
		out = append(out, Finding{Severity: SeverityHigh, Title: "HTTPS unavailable", Description: "The HTTPS endpoint could not be reached successfully.", Recommendation: "Restore HTTPS service and validate TLS connectivity.", Evidence: map[string]any{"domain": domain}})
	}
	if !hstsPresent {
		out = append(out, Finding{Severity: SeverityMedium, Title: "HSTS missing", Description: "The HTTP response does not include Strict-Transport-Security.", Recommendation: "Add the Strict-Transport-Security header to HTTPS responses.", Evidence: map[string]any{"domain": domain}})
	}
	if !cspPresent {
		out = append(out, Finding{Severity: SeverityMedium, Title: "CSP missing", Description: "The HTTP response does not include Content-Security-Policy.", Recommendation: "Add a Content-Security-Policy header appropriate for the application.", Evidence: map[string]any{"domain": domain}})
	}
	if !xfoPresent {
		out = append(out, Finding{Severity: SeverityMedium, Title: "X-Frame-Options missing", Description: "The HTTP response does not include X-Frame-Options.", Recommendation: "Add X-Frame-Options to reduce clickjacking exposure.", Evidence: map[string]any{"domain": domain}})
	}
	if !xctoPresent {
		out = append(out, Finding{Severity: SeverityMedium, Title: "X-Content-Type-Options missing", Description: "The HTTP response does not include X-Content-Type-Options.", Recommendation: "Add X-Content-Type-Options: nosniff to responses.", Evidence: map[string]any{"domain": domain}})
	}
	if serverHeader != "" {
		out = append(out, Finding{Severity: SeverityLow, Title: "Server header exposed", Description: "The HTTP response exposes a Server header.", Recommendation: "Remove or minimize the Server header if possible.", Evidence: map[string]any{"domain": domain, "server": serverHeader}})
	}
	if dnsDiscovered {
		out = append(out, Finding{Severity: SeverityInfo, Title: "DNS records discovered", Description: "Public DNS records were successfully discovered for the domain.", Recommendation: "Review the discovered records for expected external exposure.", Evidence: map[string]any{"domain": domain}})
	}
	if subdomainsDiscovered {
		out = append(out, Finding{Severity: SeverityInfo, Title: "Public subdomains discovered", Description: "Passive certificate transparency data identified public subdomains related to this domain.", Recommendation: "Review discovered hostnames and confirm they are expected and maintained.", Evidence: map[string]any{"domain": domain}})
	}

	return out
}

// Score computes the normalized 0..100 risk score from findings.
func Score(findings []Finding) int {
	score := 100
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityCritical:
			score -= 25
		case SeverityHigh:
			score -= 15
		case SeverityMedium:
			score -= 7
		case SeverityLow:
			score -= 2
		}
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// GroupBySeverity groups findings into stable report buckets.
func GroupBySeverity(findings []Finding) map[string][]Finding {
	grouped := map[string][]Finding{
		string(SeverityCritical): {},
		string(SeverityHigh):     {},
		string(SeverityMedium):   {},
		string(SeverityLow):      {},
		string(SeverityInfo):     {},
	}
	for _, finding := range findings {
		key := string(finding.Severity)
		grouped[key] = append(grouped[key], finding)
	}
	return grouped
}

// FixFirst returns findings in the order they should be addressed first.
func FixFirst(findings []Finding) []Finding {
	out := make([]Finding, len(findings))
	copy(out, findings)
	sortFindings(out)
	if len(out) > 5 {
		return out[:5]
	}
	return out
}

func sortFindings(items []Finding) {
	severityRank := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     1,
		SeverityMedium:   2,
		SeverityLow:      3,
		SeverityInfo:     4,
	}
	priorityBoost := map[string]int{
		"TLS certificate expired":          -4,
		"TLS hostname mismatch":            -3,
		"TLS certificate expiring soon":    -2,
		"DMARC missing":                    -1,
		"SPF allows +all":                  -1,
		"HTTPS unavailable":                -1,
		"Domain registration expires soon": 0,
	}
	sort.SliceStable(items, func(i, j int) bool {
		left := severityRank[items[i].Severity]*10 + priorityBoost[items[i].Title]
		right := severityRank[items[j].Severity]*10 + priorityBoost[items[j].Title]
		return left < right
	})
}

func boolValue(v any) bool {
	b, _ := v.(bool)
	return b
}

func intValue(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

func stringSlice(v any) []string {
	items, ok := v.([]any)
	if ok {
		out := make([]string, 0, len(items))
		for _, item := range items {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	if items, ok := v.([]string); ok {
		return items
	}
	return nil
}
