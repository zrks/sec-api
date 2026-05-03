package subdomains

import "testing"

func TestNormalizeHostname(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		rootDomain string
		want       string
	}{
		{name: "removes wildcard", input: "*.app.example.com", rootDomain: "example.com", want: "app.example.com"},
		{name: "ignores root domain", input: "example.com", rootDomain: "example.com", want: ""},
		{name: "ignores unrelated host", input: "other.com", rootDomain: "example.com", want: ""},
		{name: "trims suffix dot", input: "www.example.com.", rootDomain: "example.com", want: "www.example.com"},
	}

	for _, tt := range tests {
		if got := normalizeHostname(tt.input, tt.rootDomain); got != tt.want {
			t.Fatalf("%s: got %q want %q", tt.name, got, tt.want)
		}
	}
}
