package rdap

import "testing"

func TestFindRegistrarHandlesMissingRegistrantData(t *testing.T) {
	entities := []struct {
		Roles      []string `json:"roles"`
		VCardArray []any    `json:"vcardArray"`
	}{{Roles: []string{"registrar"}, VCardArray: []any{"vcard", []any{}}}}

	if got := findRegistrar(entities); got != "" {
		t.Fatalf("expected empty registrar name, got %q", got)
	}
}
