package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"brinecrypt/internal/auth"
	"brinecrypt/internal/logger"
	"brinecrypt/internal/orm"
	"brinecrypt/internal/store"

	"gorm.io/gorm"
)

func actorFromRequest(r *http.Request) string {
	if user, ok := r.Context().Value(auth.UserContextKey).(*orm.User); ok {
		return "user:" + user.Name
	}
	if sa, ok := r.Context().Value(auth.SAContextKey).(*orm.SA); ok {
		return "sa:" + sa.Namespace + "/" + sa.Name
	}
	if token, ok := r.Context().Value(auth.TokenContextKey).(*orm.CapabilityToken); ok {
		return fmt.Sprintf("token:%d", token.Id)
	}
	return "unknown"
}

func parseTimeParam(w http.ResponseWriter, r *http.Request, param string) (*time.Time, bool) {
	s := r.URL.Query().Get(param)
	if s == "" {
		return nil, true
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		http.Error(w, "invalid "+param+": use RFC3339", http.StatusBadRequest)
		return nil, false
	}
	return &t, true
}

func WriteAudit(db *gorm.DB, r *http.Request, actor, action, resource, status string) {
	entry := &orm.AuditLog{
		Actor:      actor,
		Action:     action,
		Resource:   resource,
		Status:     status,
		RemoteAddr: r.RemoteAddr,
	}
	if err := store.CreateAuditLog(db, entry); err != nil {
		logger.Error("audit log write failed: " + err.Error())
	}
}

func GetAuditLog(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMetaUser(db, r, orm.VerbTypeRead) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		q := store.AuditQuery{
			Actor:    r.URL.Query().Get("actor"),
			Action:   r.URL.Query().Get("action"),
			Resource: r.URL.Query().Get("resource"),
			Status:   r.URL.Query().Get("status"),
		}

		since, ok := parseTimeParam(w, r, "since")
		if !ok {
			return
		}
		q.Since = since

		until, ok := parseTimeParam(w, r, "until")
		if !ok {
			return
		}
		q.Until = until

		if l := r.URL.Query().Get("limit"); l != "" {
			n, err := strconv.Atoi(l)
			if err != nil || n <= 0 || n > 10000 {
				http.Error(w, "invalid limit", http.StatusBadRequest)
				return
			}
			q.Limit = n
		}

		logs, err := store.QueryAuditLogs(db, q)
		if err != nil {
			logger.Error("query audit logs: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	}
}
