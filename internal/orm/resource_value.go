package orm

import (
	"time"

	"github.com/google/uuid"
)

type ResourceValue struct {
	Uuid                uuid.UUID           `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"uuid"`
	ResourceId          uint                `gorm:"column:resource_id" json:"-"`
	Version             uint                `gorm:"column:version" json:"version"`
	Data                string              `gorm:"column:data" json:"data"`
	EncryptionAlgorithm EncryptionAlgorithm `gorm:"column:encryption_algorithm" json:"encryption_algorithm"`
	EncryptionKeyId     *uint               `gorm:"column:encryption_key_id" json:"encryption_key_id,omitempty"`
	EncryptionKey       *EncryptionKey      `gorm:"foreignKey:EncryptionKeyId;constraint:OnDelete:CASCADE;" json:"encryption_key,omitempty"`
	CreatedBy           string              `gorm:"column:created_by" json:"created_by,omitempty"`
	CreatedAt           time.Time           `gorm:"column:created_at" json:"created_at"`
	RetiredAt           *time.Time          `gorm:"column:retired_at" json:"retired_at,omitempty"`
}

func (ResourceValue) TableName() string {
	return "resource_versions"
}
