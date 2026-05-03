package authz

import (
	"fmt"
	"strings"
)

func NormalizeSubject(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty subject")
	}

	if strings.HasPrefix(s, "system:serviceaccount:") {
		parts := strings.SplitN(s, ":", 4)
		if len(parts) != 4 || parts[2] == "" || parts[3] == "" {
			return "", fmt.Errorf("invalid service account username %q", raw)
		}
		return parts[2] + "/" + parts[3], nil
	}

	parts := strings.Split(s, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid subject %q, expected <namespace>/<name>", raw)
	}
	return parts[0] + "/" + parts[1], nil
}

func NormalizeResource(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty resource")
	}

	parts := splitPathParts(s)
	if len(parts) >= 2 && parts[0] == "api" && parts[1] == "v1" {
		parts = parts[2:]
	}

	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid resource %q, expected <namespace>/<name> or /api/v1/<namespace>/<name>", raw)
	}

	return parts[0] + "/" + parts[1], nil
}

func splitPathParts(s string) []string {
	segments := strings.Split(s, "/")
	parts := make([]string, 0, len(segments))
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		parts = append(parts, seg)
	}
	return parts
}
