package store

import (
	"brinecrypt/internal/orm"

	"gorm.io/gorm"
)

func CreatePAT(db *gorm.DB, pat *orm.PAT) error {
	return db.Create(pat).Error
}

func GetPATByHash(db *gorm.DB, hash string) (*orm.PAT, error) {
	var pat orm.PAT
	err := db.Where("pat_hash = ?", hash).First(&pat).Error
	return &pat, err
}

func GetPATByID(db *gorm.DB, id uint) (*orm.PAT, error) {
	var pat orm.PAT
	err := db.First(&pat, id).Error
	return &pat, err
}

func DeletePAT(db *gorm.DB, id uint) error {
	return db.Delete(&orm.PAT{}, id).Error
}
