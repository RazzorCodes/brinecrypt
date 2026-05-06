package store

import (
	"time"

	"brinecrypt/internal/orm"

	"gorm.io/gorm"
)

func ListAnonPermissions(db *gorm.DB) ([]orm.AnonPermission, error) {
	var perms []orm.AnonPermission
	err := db.Where("expires_at IS NULL OR expires_at > ?", time.Now()).Find(&perms).Error
	return perms, err
}

func CreateAnonPermission(db *gorm.DB, p *orm.AnonPermission) error {
	return db.Create(p).Error
}

func DeleteAnonPermission(db *gorm.DB, id uint) error {
	return db.Delete(&orm.AnonPermission{}, id).Error
}
