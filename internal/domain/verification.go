package domain

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

const verificationPrefix = "drd-verify-"

// GenerateVerificationToken returns a stable, URL-safe token for DNS TXT ownership checks.
func GenerateVerificationToken() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")
}

// VerificationRecordName returns the TXT record name required to verify the domain.
func VerificationRecordName(name string) string {
	return fmt.Sprintf("_domainriskdigest.%s", strings.TrimSpace(name))
}

// VerificationRecordValue returns the TXT record value required to verify the domain.
func VerificationRecordValue(token string) string {
	return verificationPrefix + strings.TrimSpace(token)
}

// HasVerificationTXT reports whether the TXT answers contain the expected verification value.
func HasVerificationTXT(records []string, token string) bool {
	expected := VerificationRecordValue(token)
	for _, record := range records {
		if strings.TrimSpace(record) == expected {
			return true
		}
	}
	return false
}
