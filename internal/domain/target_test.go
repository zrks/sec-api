package domain

import "testing"

func TestNormalizePublicDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "plain domain", input: "example.org", want: "example.org"},
		{name: "https domain", input: "https://example.org", want: "example.org"},
		{name: "url with path and www", input: "https://www.example.org/path", want: "example.org"},
		{name: "reject localhost", input: "localhost", wantErr: true},
		{name: "reject email", input: "ops@example.org", wantErr: true},
		{name: "reject wildcard", input: "*.example.org", wantErr: true},
		{name: "reject private ip", input: "192.168.1.1", wantErr: true},
	}

	for _, tt := range tests {
		got, err := NormalizePublicDomain(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("%s: expected error", tt.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tt.name, err)
		}
		if got != tt.want {
			t.Fatalf("%s: got %q want %q", tt.name, got, tt.want)
		}
	}
}
