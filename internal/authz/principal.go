package authz

import (
	"brinecrypt/internal/orm"
	"fmt"
	"strings"
)

type PrincipalKind string

const (
	PrincipalUser  PrincipalKind = "user"
	PrincipalSA    PrincipalKind = "sa"
	PrincipalToken PrincipalKind = "token"
)

type Principal struct {
	Kind        PrincipalKind
	Name        string
	SANamespace string
	SAName      string
	TokenID     uint
}

func NewPrincipalFromUser(user *orm.User) *Principal {
	return &Principal{Kind: PrincipalUser, Name: user.Name}
}

func NewPrincipalFromSA(namespace string, name string) *Principal {
	return &Principal{Kind: PrincipalSA, SANamespace: namespace, SAName: name}
}

func NewPrincipalFromToken(token *orm.CapabilityToken) *Principal {
	return &Principal{Kind: PrincipalToken, TokenID: token.Id}
}

func ParsePrincipal(s string) (*Principal, error) {
	parts := strings.SplitN(s, "/", 3)
	switch parts[0] {
	case "user":
		if len(parts) != 2 || parts[1] == "" {
			return nil, fmt.Errorf("invalid user principal %q, expected user/<name>", s)
		}
		return &Principal{Kind: PrincipalUser, Name: parts[1]}, nil
	case "sa":
		if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
			return nil, fmt.Errorf("invalid sa principal %q, expected sa/<namespace>/<name>", s)
		}
		return &Principal{Kind: PrincipalSA, SANamespace: parts[1], SAName: parts[2]}, nil
	default:
		return nil, fmt.Errorf("unknown principal kind %q", parts[0])
	}
}

func ValidateAddPattern(pattern string) error {
	parts := strings.SplitN(pattern, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid pattern %q, expected <namespace>/<name>", pattern)
	}
	if parts[0] == "*" {
		return fmt.Errorf("wildcard namespace not allowed when granting permissions")
	}
	if parts[0] == "_" {
		return fmt.Errorf("reserved namespace not allowed when granting permissions")
	}
	if parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid pattern %q", pattern)
	}
	return nil
}

func ValidateDeletePattern(pattern string) error {
	parts := strings.SplitN(pattern, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid pattern %q, expected <namespace>/<name>", pattern)
	}
	if parts[0] == "_" {
		return fmt.Errorf("reserved namespace not allowed when revoking permissions")
	}
	if parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid pattern %q", pattern)
	}
	return nil
}
