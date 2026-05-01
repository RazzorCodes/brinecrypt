package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"brinecrypt/internal/k8s"
	"brinecrypt/internal/logger"
	"brinecrypt/internal/orm"
	"brinecrypt/internal/store"

	"gorm.io/gorm"
)

const BootstrapContextKey contextKey = "bootstrap"
const AuthMethodContextKey contextKey = "auth_method"

const (
	AuthMethodSession = "session"
	AuthMethodPAT     = "pat"
)

const (
	SessionPrefix    = "sess_"
	RefreshPrefix    = "refr_"
	PATPrefix        = "pat_"
	CapabilityPrefix = "cap_"
)

type contextKey string

const (
	UserContextKey  contextKey = "user"
	TokenContextKey contextKey = "token"
	SAContextKey    contextKey = "sa"
)

func AuthMiddleware(db *gorm.DB, next http.Handler) http.Handler {
	public := map[string]bool{
		"/auth/login": true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/_") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		if public[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		if r.Method == "POST" && r.URL.Path == "/admin/users" && k8s.IsBootstrapToken(raw) {
			ctx := context.WithValue(r.Context(), BootstrapContextKey, true)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		if raw == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch {
		case strings.HasPrefix(raw, SessionPrefix):
			user, err := resolveSession(db, raw)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), UserContextKey, user)
			ctx = context.WithValue(ctx, AuthMethodContextKey, AuthMethodSession)
			next.ServeHTTP(w, r.WithContext(ctx))

		case strings.HasPrefix(raw, PATPrefix):
			user, err := resolvePAT(db, raw)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), UserContextKey, user)
			ctx = context.WithValue(ctx, AuthMethodContextKey, AuthMethodPAT)
			next.ServeHTTP(w, r.WithContext(ctx))

		case strings.HasPrefix(raw, CapabilityPrefix):
			ct, err := resolveCapabilityToken(db, raw)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), TokenContextKey, ct)
			next.ServeHTTP(w, r.WithContext(ctx))

		case looksLikeJWT(raw):
			sa, err := resolveSAJWT(r.Context(), db, raw)
			if err != nil {
				logger.Warn("SA JWT validation failed: " + err.Error())
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), SAContextKey, sa)
			next.ServeHTTP(w, r.WithContext(ctx))

		default:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
	})
}

func looksLikeJWT(s string) bool {
	return strings.HasPrefix(s, "eyJ") && strings.Count(s, ".") == 2
}

func resolveSession(db *gorm.DB, token string) (*orm.User, error) {
	session, err := store.GetSessionByTokenHash(db, HashToken(token))
	if err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}
	return store.GetUserById(db, session.UserId)
}

func resolvePAT(db *gorm.DB, token string) (*orm.User, error) {
	pat, err := store.GetPATByHash(db, HashToken(token))
	if err != nil {
		return nil, err
	}
	if pat.Expiry != nil && time.Now().After(*pat.Expiry) {
		return nil, fmt.Errorf("PAT expired")
	}
	return store.GetUserById(db, pat.UserId)
}

func resolveCapabilityToken(db *gorm.DB, token string) (*orm.CapabilityToken, error) {
	return store.GetCapabilityTokenByHash(db, HashToken(token))
}

func resolveSAJWT(ctx context.Context, db *gorm.DB, token string) (*orm.SA, error) {
	namespace, name, err := k8s.ValidateSAToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return store.GetOrCreateSA(db, namespace, name)
}
