package authz

import (
	"fmt"
	"path"
	"strings"
	"time"

	"brinecrypt/internal/orm"
	"brinecrypt/internal/store"
	"gorm.io/gorm"
)

func Check(db *gorm.DB, principal *Principal, verb orm.Verb, namespace string, name string) (bool, error) {
	permissions, err := permissionsForPrincipal(db, principal)
	if err != nil {
		return false, err
	}

	resource := namespace + "/" + name
	for _, p := range permissions {
		if p.ExpiresAt != nil && time.Now().After(*p.ExpiresAt) {
			continue
		}
		if p.Verb != verb {
			continue
		}
		if matchesPattern(resource, p.ResourcePattern) {
			return true, nil
		}
	}

	return false, nil
}

func permissionsForPrincipal(db *gorm.DB, principal *Principal) ([]orm.Permission, error) {
	switch principal.Kind {
	case PrincipalUser:
		u, err := store.GetUser(db, principal.Name)
		if err != nil {
			return nil, err
		}
		return store.GetPermissionsForUser(db, u.Id)
	case PrincipalSA:
		sa, err := store.GetSA(db, principal.SANamespace, principal.SAName)
		if err != nil {
			return nil, err
		}
		return store.GetPermissionsForSA(db, sa.Id)
	case PrincipalToken:
		return store.GetPermissionsForCapabilityToken(db, principal.TokenID)
	default:
		return nil, fmt.Errorf("unknown principal kind %q", principal.Kind)
	}
}

// NamespacesForPrincipal returns all namespaces the principal has at least one
// non-expired verb on, mapped to the set of verbs for that namespace.
func NamespacesForPrincipal(db *gorm.DB, principal *Principal) (map[string][]orm.Verb, error) {
	permissions, err := permissionsForPrincipal(db, principal)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]orm.Verb)
	for _, p := range permissions {
		if p.ExpiresAt != nil && time.Now().After(*p.ExpiresAt) {
			continue
		}
		ns := splitSlash(p.ResourcePattern)[0]
		if ns == "*" || ns == "_" || strings.ContainsAny(ns, "*?[") {
			continue
		}
		verbs := result[ns]
		duplicate := false
		for _, v := range verbs {
			if v == p.Verb {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result[ns] = append(result[ns], p.Verb)
		}
	}
	return result, nil
}

// CheckWithAnon checks principal's own permissions, then falls through to the
// anonymous permission set. principal may be nil (unauthenticated request).
func CheckWithAnon(db *gorm.DB, principal *Principal, verb orm.Verb, namespace, name string) (bool, error) {
	if principal != nil {
		ok, err := Check(db, principal, verb, namespace, name)
		if err != nil || ok {
			return ok, err
		}
	}
	return checkAnon(db, verb, namespace, name)
}

func checkAnon(db *gorm.DB, verb orm.Verb, namespace, name string) (bool, error) {
	perms, err := store.ListAnonPermissions(db)
	if err != nil {
		return false, err
	}
	resource := namespace + "/" + name
	for _, p := range perms {
		if p.Verb != verb {
			continue
		}
		if matchesPattern(resource, p.ResourcePattern) {
			return true, nil
		}
	}
	return false, nil
}

// NamespacesForPrincipalWithAnon returns the union of the principal's namespaces
// and namespaces covered by anon permissions. principal may be nil.
func NamespacesForPrincipalWithAnon(db *gorm.DB, principal *Principal) (map[string][]orm.Verb, error) {
	result := make(map[string][]orm.Verb)

	if principal != nil {
		own, err := NamespacesForPrincipal(db, principal)
		if err != nil {
			return nil, err
		}
		for ns, verbs := range own {
			result[ns] = verbs
		}
	}

	anonPerms, err := store.ListAnonPermissions(db)
	if err != nil {
		return nil, err
	}
	for _, p := range anonPerms {
		ns := splitSlash(p.ResourcePattern)[0]
		if ns == "*" || ns == "_" || strings.ContainsAny(ns, "*?[") {
			continue
		}
		verbs := result[ns]
		duplicate := false
		for _, v := range verbs {
			if v == p.Verb {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result[ns] = append(result[ns], p.Verb)
		}
	}
	return result, nil
}

func matchesPattern(resource string, pattern string) bool {
	if pattern == "*/*" {
		return true
	}
	pParts := splitSlash(pattern)
	rParts := splitSlash(resource)
	nsMatch, _ := path.Match(pParts[0], rParts[0])
	resMatch, _ := path.Match(pParts[1], rParts[1])
	return nsMatch && resMatch
}

func splitSlash(s string) [2]string {
	for i, c := range s {
		if c == '/' {
			return [2]string{s[:i], s[i+1:]}
		}
	}
	return [2]string{s, ""}
}
