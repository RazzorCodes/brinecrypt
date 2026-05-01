package store

import (
	"brinecrypt/internal/orm"

	"gorm.io/gorm"
)

func CreatePermission(db *gorm.DB, p *orm.Permission) error {
	return db.Create(p).Error
}

func GetPermission(db *gorm.DB, id uint) (*orm.Permission, error) {
	var p orm.Permission
	err := db.First(&p, id).Error
	return &p, err
}

func DeletePermission(db *gorm.DB, id uint) error {
	return db.Delete(&orm.Permission{}, id).Error
}

func GetPermissionsForUser(db *gorm.DB, userID uint) ([]orm.Permission, error) {
	var permissions []orm.Permission
	err := db.Model(&orm.User{Id: userID}).Association("Permissions").Find(&permissions)
	return permissions, err
}

func AddPermissionToUser(db *gorm.DB, userID uint, permissionID uint) error {
	return db.Model(&orm.User{Id: userID}).Association("Permissions").Append(&orm.Permission{Id: permissionID})
}

func RevokePermissionFromUser(db *gorm.DB, userID uint, permissionID uint) error {
	return db.Model(&orm.User{Id: userID}).Association("Permissions").Delete(&orm.Permission{Id: permissionID})
}

func GetPermissionsForSA(db *gorm.DB, saID uint) ([]orm.Permission, error) {
	var permissions []orm.Permission
	err := db.Model(&orm.SA{Id: saID}).Association("Permissions").Find(&permissions)
	return permissions, err
}

func AddPermissionToSA(db *gorm.DB, saID uint, permissionID uint) error {
	return db.Model(&orm.SA{Id: saID}).Association("Permissions").Append(&orm.Permission{Id: permissionID})
}

func RevokePermissionFromSA(db *gorm.DB, saID uint, permissionID uint) error {
	return db.Model(&orm.SA{Id: saID}).Association("Permissions").Delete(&orm.Permission{Id: permissionID})
}

func RevokeMatchingPermissionsFromUser(db *gorm.DB, userID uint, verb orm.Verb, pattern string) error {
	permissions, err := GetPermissionsForUser(db, userID)
	if err != nil {
		return err
	}
	for _, p := range permissions {
		if p.Verb == verb && matchesDeletePattern(p.ResourcePattern, pattern) {
			if err := RevokePermissionFromUser(db, userID, p.Id); err != nil {
				return err
			}
		}
	}
	return nil
}

func RevokeMatchingPermissionsFromSA(db *gorm.DB, saID uint, verb orm.Verb, pattern string) error {
	permissions, err := GetPermissionsForSA(db, saID)
	if err != nil {
		return err
	}
	for _, p := range permissions {
		if p.Verb == verb && matchesDeletePattern(p.ResourcePattern, pattern) {
			if err := RevokePermissionFromSA(db, saID, p.Id); err != nil {
				return err
			}
		}
	}
	return nil
}

func matchesDeletePattern(existing, deletePattern string) bool {
	if deletePattern == "*/*" {
		return true
	}
	eParts := splitPattern(existing)
	dParts := splitPattern(deletePattern)
	nsMatch := dParts[0] == "*" || dParts[0] == eParts[0]
	resMatch := dParts[1] == "*" || dParts[1] == eParts[1]
	return nsMatch && resMatch
}

func GetPermissionsForCapabilityToken(db *gorm.DB, tokenID uint) ([]orm.Permission, error) {
	var permissions []orm.Permission
	err := db.Model(&orm.CapabilityToken{Id: tokenID}).Association("Permissions").Find(&permissions)
	return permissions, err
}

func AddPermissionToCapabilityToken(db *gorm.DB, tokenID uint, permissionID uint) error {
	return db.Model(&orm.CapabilityToken{Id: tokenID}).Association("Permissions").Append(&orm.Permission{Id: permissionID})
}

func splitPattern(pattern string) [2]string {
	for i, c := range pattern {
		if c == '/' {
			return [2]string{pattern[:i], pattern[i+1:]}
		}
	}
	return [2]string{pattern, ""}
}
