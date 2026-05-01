package migrate

import (
	"brinecrypt/internal/orm"

	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&orm.Permission{},
		&orm.User{},
		&orm.SA{},
		&orm.Session{},
		&orm.PAT{},
		&orm.CapabilityToken{},
		// ---
		&orm.Namespace{},
		&orm.EncryptionKey{},
		&orm.Resource{},
		&orm.ResourceValue{},
		// ---
		&orm.AuditLog{},
	)
}
