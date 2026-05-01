package store

import (
	"brinecrypt/internal/orm"
	"time"

	"gorm.io/gorm"
)

func CreateAuditLog(db *gorm.DB, log *orm.AuditLog) error {
	return db.Create(log).Error
}

type AuditQuery struct {
	Actor    string
	Action   string
	Resource string
	Since    *time.Time
	Until    *time.Time
	Status   string
	Limit    int
}

func QueryAuditLogs(db *gorm.DB, q AuditQuery) ([]orm.AuditLog, error) {
	limit := q.Limit
	if limit == 0 {
		limit = 100
	}
	tx := db.Model(&orm.AuditLog{})
	if q.Actor != "" {
		tx = tx.Where("actor = ?", q.Actor)
	}
	if q.Action != "" {
		tx = tx.Where("action = ?", q.Action)
	}
	if q.Resource != "" {
		tx = tx.Where("resource = ?", q.Resource)
	}
	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
	}
	if q.Since != nil {
		tx = tx.Where("created_at >= ?", q.Since)
	}
	if q.Until != nil {
		tx = tx.Where("created_at <= ?", q.Until)
	}
	var logs []orm.AuditLog
	err := tx.Order("created_at DESC").Limit(limit).Find(&logs).Error
	return logs, err
}
