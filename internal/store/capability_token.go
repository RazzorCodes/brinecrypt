package store

import (
	"brinecrypt/internal/orm"

	"gorm.io/gorm"
)

func CreateCapabilityToken(db *gorm.DB, ct *orm.CapabilityToken) error {
	return db.Create(ct).Error
}

func GetCapabilityTokenByHash(db *gorm.DB, hash string) (*orm.CapabilityToken, error) {
	var ct orm.CapabilityToken
	err := db.Preload("Permissions").Where("token_hash = ?", hash).First(&ct).Error
	return &ct, err
}

func GetCapabilityTokenByID(db *gorm.DB, id uint) (*orm.CapabilityToken, error) {
	var ct orm.CapabilityToken
	err := db.First(&ct, id).Error
	return &ct, err
}

func DeleteCapabilityToken(db *gorm.DB, id uint) error {
	return db.Delete(&orm.CapabilityToken{}, id).Error
}
