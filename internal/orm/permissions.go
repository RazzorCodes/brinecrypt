package orm

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Verb int

const (
	VerbTypeList   = 0
	VerbTypeRead   = 1
	VerbTypeWrite  = 2
	VerbTypeDelete = 3
)

var verbTypeNames = map[Verb]string{
	VerbTypeList:   "list",
	VerbTypeRead:   "read",
	VerbTypeWrite:  "write",
	VerbTypeDelete: "delete",
}

var verbTypeValues = map[string]Verb{
	"list":   VerbTypeList,
	"read":   VerbTypeRead,
	"write":  VerbTypeWrite,
	"delete": VerbTypeDelete,
}

func (v Verb) MarshalJSON() ([]byte, error) {
	s, ok := verbTypeNames[v]
	if !ok {
		return nil, fmt.Errorf("unknown Verb %d", v)
	}
	return json.Marshal(s)
}

func (v *Verb) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	vp, ok := verbTypeValues[s]
	if !ok {
		return fmt.Errorf("unknown ResourceType %q", s)
	}
	*v = vp
	return nil
}

// NoExpiry is the sentinel stored when a permission has no explicit expiry.
var NoExpiry = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

func NewPermission(pattern string, verb Verb, expiry *time.Time) Permission {
	e := NoExpiry
	if expiry != nil {
		e = *expiry
	}
	return Permission{ResourcePattern: pattern, Verb: verb, ExpiresAt: &e}
}

type Permission struct {
	Id              uint       `gorm:"primaryKey" json:"-"`
	ResourcePattern string     `gorm:"column:resource_pattern" json:"resource_pattern"`
	Verb            Verb       `gorm:"column:verb" json:"verb"`
	CreatedAt       time.Time  `gorm:"column:created_at" json:"created_at"`
	ExpiresAt       *time.Time `gorm:"column:expires_at" json:"expires_at,omitempty"`
}

func (Permission) TableName() string {
	return "permissions"
}

func ParseVerb(s string) (Verb, error) {
	v, ok := verbTypeValues[s]
	if !ok {
		return 0, fmt.Errorf("unknown verb %q", s)
	}
	return v, nil
}

// ValidateResourcePattern checks that pattern is namespace/name, rejects wildcard namespace.
func ValidateResourcePattern(pattern string) error {
	parts := strings.SplitN(pattern, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid pattern %q: must be <namespace>/<name>", pattern)
	}
	if parts[0] == "*" {
		return fmt.Errorf("wildcard namespace not allowed in pattern %q", pattern)
	}
	if parts[0] == "_" {
		return fmt.Errorf("reserved namespace not allowed in pattern %q", pattern)
	}
	return nil
}
