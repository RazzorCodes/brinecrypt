package store

import (
	"brinecrypt/internal/orm"

	"gorm.io/gorm"
)

func CreateEncryptionKey(db *gorm.DB, encryptedDEK string, kekVersion uint) (*orm.EncryptionKey, error) {
	key := orm.EncryptionKey{
		EncryptedDEK: encryptedDEK,
		KekVersion:   kekVersion,
	}
	err := db.Create(&key).Error
	return &key, err
}

func GetEncryptionKey(db *gorm.DB, id uint) (*orm.EncryptionKey, error) {
	var key orm.EncryptionKey
	err := db.First(&key, id).Error
	return &key, err
}

func ListEncryptionKeysByKEKVersion(db *gorm.DB, kekVersion uint) ([]orm.EncryptionKey, error) {
	var keys []orm.EncryptionKey
	err := db.Where("kek_version = ?", kekVersion).Find(&keys).Error
	return keys, err
}
