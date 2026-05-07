package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"brinecrypt/internal/auth"
	"brinecrypt/internal/logger"
	"brinecrypt/internal/orm"
	"brinecrypt/internal/store"

	"gorm.io/gorm"
)

func anonTokenTTL() time.Duration {
	if s := os.Getenv("ANON_TOKEN_TTL_SECONDS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Hour
}

type LoginRequestBody struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type LoginResponseBody struct {
	SessionToken string `json:"session_token"`
	RefreshToken string `json:"refresh_token"`
}

func Login(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request LoginRequestBody
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.User == "" || request.Pass == "" {
			http.Error(w, "malformed input", http.StatusBadRequest)
			return
		}

		tokens, err := auth.Login(db, request.User, request.Pass)
		if err != nil {
			WriteAudit(db, r, "user:"+request.User, orm.ActionAuthLogin, "user:"+request.User, orm.AuditStatusDenied)
			http.Error(w, "incorrect user or password", http.StatusUnauthorized)
			return
		}

		WriteAudit(db, r, "user:"+request.User, orm.ActionAuthLogin, "user:"+request.User, orm.AuditStatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(LoginResponseBody{
			SessionToken: tokens.SessionToken,
			RefreshToken: tokens.RefreshToken,
		})
	}
}

type RefreshSessionRequest struct {
	Token string `json:"token"`
}

func Refresh(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var request RefreshSessionRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Token == "" {
			http.Error(w, "malformed input", http.StatusBadRequest)
			return
		}

		tokens, err := auth.Refresh(db, request.Token)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		actor := actorFromRequest(r)
		WriteAudit(db, r, actor, orm.ActionAuthRefresh, actor, orm.AuditStatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(LoginResponseBody{
			SessionToken: tokens.SessionToken,
			RefreshToken: tokens.RefreshToken,
		})
	}
}

func Logout(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		actor := actorFromRequest(r)
		if err := auth.Logout(db, token); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		WriteAudit(db, r, actor, orm.ActionAuthLogout, actor, orm.AuditStatusOK)
		w.WriteHeader(http.StatusNoContent)
	}
}

func AnonToken(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		anonPerms, err := store.ListAnonPermissions(db)
		if err != nil {
			logger.Error("list anon permissions: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if len(anonPerms) == 0 {
			http.Error(w, "anonymous access not configured", http.StatusServiceUnavailable)
			return
		}

		raw, err := auth.GenerateToken()
		if err != nil {
			logger.Error("generate anon token: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		token := auth.CapabilityPrefix + raw
		ttl := anonTokenTTL()
		exp := time.Now().Add(ttl)

		if err := db.Transaction(func(tx *gorm.DB) error {
			ct := &orm.CapabilityToken{
				IssuedBy:  nil,
				TokenHash: auth.HashToken(token),
				ExpiresAt: &exp,
			}
			if err := store.CreateCapabilityToken(tx, ct); err != nil {
				return err
			}
			for _, ap := range anonPerms {
				p := orm.NewPermission(ap.ResourcePattern, ap.Verb, ap.ExpiresAt)
				if err := store.CreatePermission(tx, &p); err != nil {
					return err
				}
				if err := store.AddPermissionToCapabilityToken(tx, ct.Id, p.Id); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			logger.Error("create anon capability token: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		WriteAudit(db, r, "anon", orm.ActionAuthAnon, "anon", orm.AuditStatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token":      token,
			"expires_in": int(ttl.Seconds()),
		})
	}
}
