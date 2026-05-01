package orm

import "time"

type Namespace struct {
	Id        uint      `gorm:"primaryKey" json:"-"`
	Name      string    `gorm:"column:name" json:"name"`
	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
}

func (Namespace) TableName() string {
	return "namespaces"
}
