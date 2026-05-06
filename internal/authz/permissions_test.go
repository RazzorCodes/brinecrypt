package authz

import "testing"

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		resource string
		pattern  string
		want     bool
	}{
		// global wildcard
		{"names-pace/re-source", "*/*", true},
		{"any/thing", "*/*", true},

		// exact match
		{"prod/db", "prod/db", true},
		{"prod/db", "staging/db", false},

		// full namespace wildcard
		{"prod/db", "prod/*", true},
		{"staging/db", "prod/*", false},

		// partial namespace glob
		{"names-pace/re-source", "names-*/*-source", true},
		{"namespace/r-source", "names-*/*-source", false},
		{"names-/re-source", "names-*/*-source", true},

		// partial resource glob
		{"prod/db-primary", "prod/db-*", true},
		{"prod/db-replica", "prod/db-*", true},
		{"prod/other", "prod/db-*", false},

		// suffix glob on resource
		{"prod/re-source", "prod/*-source", true},
		{"prod/source", "prod/*-source", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_vs_"+tt.resource, func(t *testing.T) {
			got := matchesPattern(tt.resource, tt.pattern)
			if got != tt.want {
				t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.resource, tt.pattern, got, tt.want)
			}
		})
	}
}
