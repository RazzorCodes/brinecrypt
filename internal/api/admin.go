package api

import (
	"encoding/json"
	"net/http"
	"time"

	"brinecrypt/internal/auth"
	"brinecrypt/internal/authz"
	"brinecrypt/internal/logger"
	"brinecrypt/internal/orm"
	"brinecrypt/internal/store"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const metaNS = "_"
const metaUsersResource = "users"

type userResponse struct {
	Name        string           `json:"name"`
	Email       string           `json:"email"`
	CreatedAt   time.Time        `json:"created_at"`
	Permissions []orm.Permission `json:"permissions"`
}

func requireMetaUser(db *gorm.DB, r *http.Request, verb orm.Verb) bool {
	method, _ := r.Context().Value(auth.AuthMethodContextKey).(string)
	if method != auth.AuthMethodSession {
		return false
	}
	principal, ok := principalFromContext(r)
	if !ok {
		return false
	}
	ok, _ = authz.Check(db, principal, verb, metaNS, metaUsersResource)
	return ok
}

func CreateUser(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		isBootstrap, _ := r.Context().Value(auth.BootstrapContextKey).(bool)
		if !isBootstrap && !requireMetaUser(db, r, orm.VerbTypeWrite) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		var body struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			Pass  string `json:"pass"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" || body.Pass == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(body.Pass), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("bcrypt failed: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		u := &orm.User{Name: body.Name, Email: body.Email, Pass: string(hash)}
		if err := store.CreateUser(db, u); err != nil {
			logger.Error("create user failed: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if isBootstrap {
			for _, verb := range []orm.Verb{orm.VerbTypeList, orm.VerbTypeRead, orm.VerbTypeWrite, orm.VerbTypeDelete} {
				p := orm.NewPermission(metaNS+"/"+metaUsersResource, verb, nil)
				if err := store.CreatePermission(db, &p); err != nil {
					logger.Error("bootstrap grant failed: " + err.Error())
					continue
				}
				store.AddPermissionToUser(db, u.Id, p.Id)
			}
		}

		WriteAudit(db, r, actorFromRequest(r), orm.ActionUserCreate, metaNS+"/"+body.Name, orm.AuditStatusOK)
		w.WriteHeader(http.StatusNoContent)
	}
}

type permissionEntry struct {
	Verb            orm.Verb   `json:"verb"`
	ResourcePattern string     `json:"resource_pattern"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
}

type permissionsRequestBody struct {
	Principal   string            `json:"principal"`
	Permissions []permissionEntry `json:"permissions"`
}

func ListUsers(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMetaUser(db, r, orm.VerbTypeList) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		users, err := store.ListUsers(db)
		if err != nil {
			logger.Error("list users: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		resp := make([]string, 0, len(users))
		for _, u := range users {
			resp = append(resp, u.Name)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func GetUserByName(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMetaUser(db, r, orm.VerbTypeRead) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		u, err := store.GetUser(db, r.PathValue("name"))
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		perms, _ := store.GetPermissionsForUser(db, u.Id)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userResponse{Name: u.Name, Email: u.Email, CreatedAt: u.CreatedAt, Permissions: perms})
	}
}

func DeleteUserByName(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMetaUser(db, r, orm.VerbTypeDelete) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		name := r.PathValue("name")
		if err := store.DeleteUser(db, name); err != nil {
			logger.Error("delete user: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		WriteAudit(db, r, actorFromRequest(r), orm.ActionUserDelete, metaNS+"/"+name, orm.AuditStatusOK)
		w.WriteHeader(http.StatusNoContent)
	}
}

func GrantPermissions(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMetaUser(db, r, orm.VerbTypeWrite) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var body permissionsRequestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			logger.Error("grant permissions decode failed: " + err.Error())
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if body.Principal == "" || len(body.Permissions) == 0 {
			logger.Warn("grant permissions: missing principal or permissions")
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		principal, err := authz.ParsePrincipal(body.Principal)
		if err != nil {
			logger.Warn("invalid principal: " + err.Error())
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		for _, entry := range body.Permissions {
			if err := authz.ValidateAddPattern(entry.ResourcePattern); err != nil {
				logger.Warn("invalid pattern: " + err.Error())
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
		}

		var principalID uint
		switch principal.Kind {
		case authz.PrincipalUser:
			u, err := store.GetUser(db, principal.Name)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			principalID = u.Id
		case authz.PrincipalSA:
			sa, err := store.GetSA(db, principal.SANamespace, principal.SAName)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			principalID = sa.Id
		}

		for _, entry := range body.Permissions {
			p := orm.NewPermission(entry.ResourcePattern, entry.Verb, entry.ExpiresAt)
			if err := store.CreatePermission(db, &p); err != nil {
				logger.Error("create permission failed: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			switch principal.Kind {
			case authz.PrincipalUser:
				err = store.AddPermissionToUser(db, principalID, p.Id)
			case authz.PrincipalSA:
				err = store.AddPermissionToSA(db, principalID, p.Id)
			}
			if err != nil {
				logger.Error("link permission failed: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
		}

		WriteAudit(db, r, actorFromRequest(r), orm.ActionPermGrant, body.Principal, orm.AuditStatusOK)
		w.WriteHeader(http.StatusNoContent)
	}
}

func RevokePermissions(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMetaUser(db, r, orm.VerbTypeWrite) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var body permissionsRequestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			logger.Error("revoke permissions decode failed: " + err.Error())
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if body.Principal == "" || len(body.Permissions) == 0 {
			logger.Warn("revoke permissions: missing principal or permissions")
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		principal, err := authz.ParsePrincipal(body.Principal)
		if err != nil {
			logger.Warn("invalid principal: " + err.Error())
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		for _, entry := range body.Permissions {
			if err := authz.ValidateDeletePattern(entry.ResourcePattern); err != nil {
				logger.Warn("invalid pattern: " + err.Error())
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
		}

		var principalID uint
		switch principal.Kind {
		case authz.PrincipalUser:
			u, err := store.GetUser(db, principal.Name)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			principalID = u.Id
		case authz.PrincipalSA:
			sa, err := store.GetSA(db, principal.SANamespace, principal.SAName)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			principalID = sa.Id
		}

		for _, entry := range body.Permissions {
			switch principal.Kind {
			case authz.PrincipalUser:
				err = store.RevokeMatchingPermissionsFromUser(db, principalID, entry.Verb, entry.ResourcePattern)
			case authz.PrincipalSA:
				err = store.RevokeMatchingPermissionsFromSA(db, principalID, entry.Verb, entry.ResourcePattern)
			}
			if err != nil {
				logger.Error("revoke permission failed: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
		}

		WriteAudit(db, r, actorFromRequest(r), orm.ActionPermRevoke, body.Principal, orm.AuditStatusOK)
		w.WriteHeader(http.StatusNoContent)
	}
}
