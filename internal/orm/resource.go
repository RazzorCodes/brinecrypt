package orm

import (
	"encoding/json"
	"fmt"
	"time"
)

type ResourceType int

const (
	ResourceTypeUndefined ResourceType = 0
	ResourceTypeCleartext ResourceType = 1
	ResourceTypeEncrypted ResourceType = 2
)

var resourceTypeNames = map[ResourceType]string{
	ResourceTypeUndefined: "undefined",
	ResourceTypeCleartext: "cleartext",
	ResourceTypeEncrypted: "encrypted",
}

var resourceTypeValues = map[string]ResourceType{
	"undefined": ResourceTypeUndefined,
	"cleartext": ResourceTypeCleartext,
	"encrypted": ResourceTypeEncrypted,
}

func (t ResourceType) MarshalJSON() ([]byte, error) {
	s, ok := resourceTypeNames[t]
	if !ok {
		return nil, fmt.Errorf("unknown ResourceType %d", t)
	}
	return json.Marshal(s)
}

func (t *ResourceType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, ok := resourceTypeValues[s]
	if !ok {
		return fmt.Errorf("unknown ResourceType %q", s)
	}
	*t = v
	return nil
}

type Resource struct {
	Id          uint         `gorm:"primaryKey" json:"-"`
	NamespaceId uint         `gorm:"column:namespace_id" json:"-"`
	Namespace   Namespace    `gorm:"foreignKey:NamespaceId" json:"namespace,omitempty"`
	Name        string       `gorm:"column:name" json:"name"`
	Type        ResourceType `gorm:"column:resource_type" json:"type"`
	CreatedAt   time.Time    `gorm:"column:created_at" json:"created_at"`
	CreatedBy   string       `gorm:"column:created_by" json:"created_by"`
	RetiredAt   *time.Time   `gorm:"column:retired_at" json:"retired_at,omitempty"`

	Value *ResourceValue `gorm:"foreignKey:ResourceId;constraint:OnDelete:CASCADE;" json:"value,omitempty"`
}

func (Resource) TableName() string {
	return "resources"
}
