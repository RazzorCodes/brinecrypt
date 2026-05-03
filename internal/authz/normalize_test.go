package authz

import "testing"

func TestNormalizeSubject(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "tokenreview username", raw: "system:serviceaccount:test-ns:test-sa", want: "test-ns/test-sa"},
		{name: "canonical", raw: "test-ns/test-sa", want: "test-ns/test-sa"},
		{name: "invalid tokenreview format", raw: "system:serviceaccount:test-ns", wantErr: true},
		{name: "invalid plain", raw: "foo", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeSubject(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeSubject(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestNormalizeResource(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "canonical", raw: "test-ns/test-rs", want: "test-ns/test-rs"},
		{name: "api prefix with leading slash", raw: "/api/v1/test-ns/test-rs", want: "test-ns/test-rs"},
		{name: "api prefix", raw: "api/v1/test-ns/test-rs", want: "test-ns/test-rs"},
		{name: "redundant slashes", raw: "///api/v1///test-ns///test-rs///", want: "test-ns/test-rs"},
		{name: "too short", raw: "test-rs", wantErr: true},
		{name: "too long", raw: "test-ns/test-rs/extra", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeResource(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeResource(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
