package store

import (
	"brinecrypt/internal/orm"

	"gorm.io/gorm"
)

func GetResourceValueByUUID(db *gorm.DB, uuid string) (*orm.ResourceValue, error) {
	var rv orm.ResourceValue
	err := db.Preload("EncryptionKey").Where("uuid = ?", uuid).First(&rv).Error
	return &rv, err
}

func GetLatestResourceValue(db *gorm.DB, resourceID uint) (*orm.ResourceValue, error) {
	var rv orm.ResourceValue
	err := db.Preload("EncryptionKey").
		Where("resource_id = ?", resourceID).
		Order("version DESC").
		First(&rv).Error
	return &rv, err
}

func GetResourceVersion(db *gorm.DB, resourceID uint, version uint) (*orm.ResourceValue, error) {
	var rv orm.ResourceValue
	err := db.Preload("EncryptionKey").
		Where("resource_id = ? AND version = ?", resourceID, version).
		First(&rv).Error
	return &rv, err
}

func ListResourceVersions(db *gorm.DB, resourceID uint) ([]orm.ResourceValue, error) {
	var versions []orm.ResourceValue
	err := db.
		Where("resource_id = ?", resourceID).
		Order("version ASC").
		Find(&versions).Error
	return versions, err
}

func CountResourceVersions(db *gorm.DB, resourceID uint) (int64, error) {
	var count int64
	err := db.Model(&orm.ResourceValue{}).Where("resource_id = ?", resourceID).Count(&count).Error
	return count, err
}

func CreateResourceValue(db *gorm.DB, rv *orm.ResourceValue) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var max uint
		if err := tx.Model(&orm.ResourceValue{}).
			Where("resource_id = ?", rv.ResourceId).
			Select("COALESCE(MAX(version), 0)").
			Scan(&max).Error; err != nil {
			return err
		}
		rv.Version = max + 1
		return tx.Create(rv).Error
	})
}
