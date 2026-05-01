package orm

import "time"

type Session struct {
	Id               uint      `gorm:"primaryKey" json:"-"`
	UserId           uint      `gorm:"column:user_id" json:"-"`
	User             User      `gorm:"foreignKey:UserId" json:"-"`
	TokenHash        string    `gorm:"column:token_hash" json:"-"`
	RefreshTokenHash string    `gorm:"column:refresh_token_hash" json:"-"`
	ExpiresAt        time.Time `gorm:"column:expires_at" json:"expires_at"`
	CreatedAt        time.Time `gorm:"column:created_at" json:"created_at"`
}

func (Session) TableName() string {
	return "sessions"
}
