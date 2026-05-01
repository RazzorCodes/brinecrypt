package store

import (
	"brinecrypt/internal/orm"

	"gorm.io/gorm"
)

func GetNamespace(db *gorm.DB, name string) (*orm.Namespace, error) {
	var ns orm.Namespace
	err := db.Where("name = ?", name).First(&ns).Error
	return &ns, err
}

func CreateNamespace(db *gorm.DB, name string) (*orm.Namespace, error) {
	ns := orm.Namespace{Name: name}
	err := db.Create(&ns).Error
	return &ns, err
}

func ListNamespaces(db *gorm.DB) ([]orm.Namespace, error) {
	var namespaces []orm.Namespace
	err := db.Find(&namespaces).Error
	return namespaces, err
}

func DeleteNamespace(db *gorm.DB, name string) error {
	return db.Where("name = ?", name).Delete(&orm.Namespace{}).Error
}
