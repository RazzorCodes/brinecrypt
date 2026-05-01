package store

import (
	"brinecrypt/internal/orm"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func GetResource(db *gorm.DB, namespace string, name string) (*orm.Resource, error) {
	var r orm.Resource
	err := db.
		Joins("JOIN namespaces ON namespaces.id = resources.namespace_id").
		Where("namespaces.name = ? AND resources.name = ?", namespace, name).
		Preload("Namespace").
		Preload("Value", func(db *gorm.DB) *gorm.DB {
			return db.Preload("EncryptionKey").Order("version DESC").Limit(1)
		}).
		First(&r).Error
	return &r, err
}

func ListResources(db *gorm.DB, namespace string) ([]orm.Resource, error) {
	var resources []orm.Resource
	err := db.
		Joins("JOIN namespaces ON namespaces.id = resources.namespace_id").
		Where("namespaces.name = ?", namespace).
		Find(&resources).Error
	return resources, err
}

func GetResourceByID(db *gorm.DB, id uint) (*orm.Resource, error) {
	var r orm.Resource
	err := db.Preload("Namespace").First(&r, id).Error
	return &r, err
}

func CreateResource(db *gorm.DB, r *orm.Resource) error {
	return db.Create(r).Error
}

func DeleteResource(db *gorm.DB, namespace string, name string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var r orm.Resource
		err := tx.
			Joins("JOIN namespaces ON namespaces.id = resources.namespace_id").
			Where("namespaces.name = ? AND resources.name = ?", namespace, name).
			First(&r).Error
		if err != nil {
			return err
		}

		return tx.Select(clause.Associations).Delete(&r).Error
	})
}
