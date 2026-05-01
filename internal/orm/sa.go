package orm

import "time"

type SA struct {
	Id          uint         `gorm:"primaryKey" json:"-"`
	Namespace   string       `gorm:"column:sa_namespace" json:"namespace"`
	Name        string       `gorm:"column:sa_name" json:"name"`
	SyncedAt    time.Time    `gorm:"column:synced_at" json:"synced_at"`
	Permissions []Permission `gorm:"many2many:sa_permissions;constraint:OnDelete:CASCADE;" json:"permissions,omitempty"`
}

func (SA) TableName() string {
	return "service_accounts"
}
