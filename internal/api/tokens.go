package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"brinecrypt/internal/auth"
	"brinecrypt/internal/authz"
	"brinecrypt/internal/logger"
	"brinecrypt/internal/orm"
	"brinecrypt/internal/store"

	"gorm.io/gorm"
)

func IssuePAT(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(auth.UserContextKey).(*orm.User)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var body struct {
			Expiry *time.Time `json:"expiry,omitempty"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		raw, err := auth.GenerateToken()
		if err != nil {
			logger.Error("generate PAT: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		token := auth.PATPrefix + raw

		pat := &orm.PAT{
			UserId:  user.Id,
			PATHash: auth.HashToken(token),
			Expiry:  body.Expiry,
		}
		if err := store.CreatePAT(db, pat); err != nil {
			logger.Error("create PAT: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		WriteAudit(db, r, "user:"+user.Name, orm.ActionTokenPATIssue, "user:"+user.Name, orm.AuditStatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}

func RevokePAT(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(auth.UserContextKey).(*orm.User)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		pat, err := store.GetPATByID(db, uint(id))
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if pat.UserId != user.Id {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := store.DeletePAT(db, pat.Id); err != nil {
			logger.Error("delete PAT: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		WriteAudit(db, r, "user:"+user.Name, orm.ActionTokenPATRevoke, "user:"+user.Name, orm.AuditStatusOK)
		w.WriteHeader(http.StatusNoContent)
	}
}

func IssueCapabilityToken(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(auth.UserContextKey).(*orm.User)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		principal := authz.NewPrincipalFromUser(user)

		var body struct {
			Permissions []permissionEntry `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Permissions) == 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		for _, entry := range body.Permissions {
			parts := strings.SplitN(entry.ResourcePattern, "/", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			allowed, err := authz.Check(db, principal, entry.Verb, parts[0], parts[1])
			if err != nil || !allowed {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		raw, err := auth.GenerateToken()
		if err != nil {
			logger.Error("generate capability token: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		token := auth.CapabilityPrefix + raw

		ct := &orm.CapabilityToken{
			IssuedBy:  &user.Id,
			TokenHash: auth.HashToken(token),
		}
		if err := store.CreateCapabilityToken(db, ct); err != nil {
			logger.Error("create capability token: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		for _, entry := range body.Permissions {
			p := orm.NewPermission(entry.ResourcePattern, entry.Verb, entry.ExpiresAt)
			if err := store.CreatePermission(db, &p); err != nil {
				logger.Error("create permission: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			if err := store.AddPermissionToCapabilityToken(db, ct.Id, p.Id); err != nil {
				logger.Error("link permission to capability token: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
		}

		WriteAudit(db, r, "user:"+user.Name, orm.ActionTokenCapIssue, "user:"+user.Name, orm.AuditStatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}

func RevokeCapabilityToken(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(auth.UserContextKey).(*orm.User)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		ct, err := store.GetCapabilityTokenByID(db, uint(id))
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if ct.IssuedBy == nil || *ct.IssuedBy != user.Id {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := store.DeleteCapabilityToken(db, ct.Id); err != nil {
			logger.Error("delete capability token: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		WriteAudit(db, r, "user:"+user.Name, orm.ActionTokenCapRevoke, "user:"+user.Name, orm.AuditStatusOK)
		w.WriteHeader(http.StatusNoContent)
	}
}
