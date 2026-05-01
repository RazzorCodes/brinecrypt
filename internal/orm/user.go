package orm

import "time"

type User struct {
	Id          uint         `gorm:"primaryKey" json:"-"`
	Name        string       `gorm:"column:name" json:"name"`
	Email       string       `gorm:"column:email" json:"email,omitempty"`
	Pass        string       `gorm:"column:pass" json:"-"`
	CreatedAt   time.Time         `gorm:"column:created_at" json:"created_at"`
	Permissions []Permission      `gorm:"many2many:user_permissions;constraint:OnDelete:CASCADE;" json:"permissions,omitempty"`
	Sessions    []Session         `gorm:"foreignKey:UserId;constraint:OnDelete:CASCADE;" json:"-"`
	Pats        []PAT             `gorm:"foreignKey:UserId;constraint:OnDelete:CASCADE;" json:"-"`
	Tokens      []CapabilityToken `gorm:"foreignKey:IssuedBy;constraint:OnDelete:CASCADE;" json:"-"`
}

func (User) TableName() string {
	return "users"
}
