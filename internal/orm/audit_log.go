package orm

import "time"

type AuditLog struct {
	Id         uint      `gorm:"primaryKey" json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Actor      string    `json:"actor"`      // "user:alice", "sa:ns/name", "token:42"
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`   // "namespace/name" or descriptive target
	Status     string    `json:"status"`     // "ok", "denied", "error"
	RemoteAddr string    `json:"remote_addr"`
}

const (
	ActionResourceRead   = "resource.read"
	ActionResourceWrite  = "resource.write"
	ActionResourceDelete = "resource.delete"
	ActionResourceList   = "resource.list"

	ActionUserCreate  = "user.create"
	ActionUserDelete  = "user.delete"
	ActionPermGrant   = "permission.grant"
	ActionPermRevoke  = "permission.revoke"

	ActionAuthLogin   = "auth.login"
	ActionAuthLogout  = "auth.logout"
	ActionAuthRefresh = "auth.refresh"

	ActionTokenPATIssue  = "token.pat.issue"
	ActionTokenPATRevoke = "token.pat.revoke"
	ActionTokenCapIssue  = "token.capability.issue"
	ActionTokenCapRevoke = "token.capability.revoke"

	AuditStatusOK     = "ok"
	AuditStatusDenied = "denied"
	AuditStatusError  = "error"
)
