package store

import (
	"brinecrypt/internal/orm"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func GetUser(db *gorm.DB, name string) (*orm.User, error) {
	var u orm.User
	err := db.Where("name = ?", name).First(&u).Error
	return &u, err
}

func GetUserById(db *gorm.DB, id uint) (*orm.User, error) {
	var u orm.User
	err := db.First(&u, id).Error
	return &u, err
}

func CreateUser(db *gorm.DB, u *orm.User) error {
	return db.Create(u).Error
}

func ListUsers(db *gorm.DB) ([]orm.User, error) {
	var users []orm.User
	err := db.Find(&users).Error
	return users, err
}

func DeleteUser(db *gorm.DB, name string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var u orm.User
		if err := tx.Where("name = ?", name).First(&u).Error; err != nil {
			return err
		}

		// Delete associations first to avoid FK violations
		if err := tx.Select(clause.Associations).Delete(&u).Error; err != nil {
			return err
		}

		return nil
	})
}
