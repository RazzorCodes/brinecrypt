package orm

import "time"

type AnonPermission struct {
	Id              uint       `gorm:"primaryKey" json:"id"`
	ResourcePattern string     `gorm:"column:resource_pattern" json:"resource_pattern"`
	Verb            Verb       `gorm:"column:verb" json:"verb"`
	ExpiresAt       *time.Time `gorm:"column:expires_at" json:"expires_at,omitempty"`
	CreatedAt       time.Time  `gorm:"column:created_at" json:"created_at"`
}

func (AnonPermission) TableName() string { return "anon_permissions" }
