package orm

import "time"

type CapabilityToken struct {
	Id          uint         `gorm:"primaryKey" json:"-"`
	IssuedBy    *uint        `gorm:"column:issued_by" json:"-"`
	Issuer      *User        `gorm:"foreignKey:IssuedBy" json:"-"`
	TokenHash   string       `gorm:"column:token_hash" json:"-"`
	CreatedAt   time.Time    `gorm:"column:created_at" json:"created_at"`
	Permissions []Permission `gorm:"many2many:capability_token_permissions;constraint:OnDelete:CASCADE;" json:"permissions,omitempty"`
}

func (CapabilityToken) TableName() string {
	return "capability_tokens"
}
