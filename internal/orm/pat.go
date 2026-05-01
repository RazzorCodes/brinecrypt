package orm

import "time"

type PAT struct {
	Id         uint       `gorm:"primaryKey" json:"-"`
	UserId     uint       `gorm:"column:user_id" json:"-"`
	User       User       `gorm:"foreignKey:UserId" json:"-"`
	PATHash    string     `gorm:"column:pat_hash" json:"-"`
	Expiry     *time.Time `gorm:"column:expiry" json:"expiry,omitempty"`
	CreatedAt  time.Time  `gorm:"column:created_at" json:"created_at"`
	LastUsedAt *time.Time `gorm:"column:last_used_at" json:"last_used_at,omitempty"`
}

func (PAT) TableName() string {
	return "pats"
}
