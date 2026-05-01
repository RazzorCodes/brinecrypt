package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"brinecrypt/internal/auth"
	"brinecrypt/internal/authz"
	"brinecrypt/internal/crypto"
	"brinecrypt/internal/logger"
	"brinecrypt/internal/orm"
	"brinecrypt/internal/store"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ResourceSummary struct {
	Name      string           `json:"name"`
	Type      orm.ResourceType `json:"type"`
	CreatedAt time.Time        `json:"created_at"`
	CreatedBy string           `json:"created_by"`
	RetiredAt *time.Time       `json:"retired_at,omitempty"`
}

func SummarizeResource(r orm.Resource) ResourceSummary {
	return ResourceSummary{
		Name:      r.Name,
		Type:      r.Type,
		CreatedAt: r.CreatedAt,
		CreatedBy: r.CreatedBy,
		RetiredAt: r.RetiredAt,
	}
}

type ResourceValueSummary struct {
	Uuid                uuid.UUID               `json:"uuid"`
	Version             uint                    `json:"version"`
	CreatedBy           string                  `json:"created_by"`
	CreatedAt           time.Time               `json:"created_at"`
	RetiredAt           *time.Time              `json:"retired_at,omitempty"`
	EncryptionAlgorithm orm.EncryptionAlgorithm `json:"encryption_algorithm"`
}

func SummarizeResourceValue(r orm.ResourceValue) ResourceValueSummary {
	return ResourceValueSummary{
		Uuid:                r.Uuid,
		Version:             r.Version,
		CreatedAt:           r.CreatedAt,
		CreatedBy:           r.CreatedBy,
		RetiredAt:           r.RetiredAt,
		EncryptionAlgorithm: r.EncryptionAlgorithm,
	}
}

func principalFromContext(r *http.Request) (*authz.Principal, bool) {
	if user, ok := r.Context().Value(auth.UserContextKey).(*orm.User); ok {
		return authz.NewPrincipalFromUser(user), true
	}
	if token, ok := r.Context().Value(auth.TokenContextKey).(*orm.CapabilityToken); ok {
		return authz.NewPrincipalFromToken(token), true
	}
	if sa, ok := r.Context().Value(auth.SAContextKey).(*orm.SA); ok {
		return authz.NewPrincipalFromSA(sa.Namespace, sa.Name), true
	}
	return nil, false
}

func decryptValue(rv *orm.ResourceValue) error {
	if rv.EncryptionAlgorithm == orm.EncryptionAlgorithmUndefined {
		return nil
	}
	if rv.EncryptionKey == nil {
		return fmt.Errorf("encryption key not loaded for version %d", rv.Version)
	}
	kek, err := crypto.GetKEK()
	if err != nil {
		return err
	}
	dek, err := crypto.DecryptDEK(rv.EncryptionKey.EncryptedDEK, kek)
	if err != nil {
		return err
	}
	plaintext, err := crypto.DecryptValue(rv.Data, dek)
	if err != nil {
		return err
	}
	rv.Data = plaintext
	return nil
}

func GetResourceValue(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		uuidStr := r.PathValue("uuid")
		rv, err := store.GetResourceValueByUUID(db, uuidStr)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		resource, err := store.GetResourceByID(db, rv.ResourceId)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		allowed, err := authz.Check(db, principal, orm.VerbTypeRead, resource.Namespace.Name, resource.Name)
		if err != nil || !allowed {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := decryptValue(rv); err != nil {
			logger.Error("decrypt resource value: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceRead, resource.Namespace.Name+"/"+resource.Name, orm.AuditStatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rv)
	}
}

func GetResource(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		namespace := r.PathValue("namespace")
		name := r.PathValue("name")

		allowed, err := authz.Check(db, principal, orm.VerbTypeRead, namespace, name)
		if err != nil || !allowed {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		resource, err := store.GetResource(db, namespace, name)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if resource.Value != nil {
			if err := decryptValue(resource.Value); err != nil {
				logger.Error("decrypt resource value: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
		}

		WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceRead, namespace+"/"+name, orm.AuditStatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resource)
	}
}

func ListResourceVersions(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		namespace := r.PathValue("namespace")
		name := r.PathValue("name")

		allowed, err := authz.Check(db, principal, orm.VerbTypeList, namespace, name)
		if err != nil || !allowed {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		resource, err := store.GetResource(db, namespace, name)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		versions, err := store.ListResourceVersions(db, resource.Id)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		var summary []ResourceValueSummary
		for _, v := range versions {
			summary = append(summary, SummarizeResourceValue(v))
		}

		WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceList, namespace+"/"+name+"/versions", orm.AuditStatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	}
}

func ListResourcesInNamespace(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		namespace := r.PathValue("namespace")

		allowed, err := authz.Check(db, principal, orm.VerbTypeList, namespace, "*")
		if err != nil || !allowed {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		resources, err := store.ListResources(db, namespace)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		var summary []ResourceSummary
		for _, resource := range resources {
			summary = append(summary, SummarizeResource(resource))
		}

		WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceList, namespace+"/*", orm.AuditStatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	}
}

func GetResourceByVersion(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		namespace := r.PathValue("namespace")
		name := r.PathValue("name")
		versionStr := r.PathValue("version")

		version, err := strconv.ParseUint(versionStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid version number", http.StatusBadRequest)
			return
		}

		allowed, err := authz.Check(db, principal, orm.VerbTypeRead, namespace, name)
		if err != nil || !allowed {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		resource, err := store.GetResource(db, namespace, name)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		rv, err := store.GetResourceVersion(db, resource.Id, uint(version))
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if err := decryptValue(rv); err != nil {
			logger.Error("decrypt resource value: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceRead, namespace+"/"+name, orm.AuditStatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rv)
	}
}

func DeleteResource(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		namespace := r.PathValue("namespace")
		name := r.PathValue("name")

		allowed, err := authz.Check(db, principal, orm.VerbTypeDelete, namespace, name)
		if err != nil || !allowed {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := store.DeleteResource(db, namespace, name); err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceDelete, namespace+"/"+name, orm.AuditStatusOK)
		w.WriteHeader(http.StatusNoContent)
	}
}

func PutResource(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		namespace := r.PathValue("namespace")
		name := r.PathValue("name")

		var body struct {
			Type  orm.ResourceType `json:"type"`
			Value string           `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		allowed, err := authz.Check(db, principal, orm.VerbTypeWrite, namespace, name)
		if err != nil || !allowed {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ns, err := store.GetNamespace(db, namespace)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				ns, err = store.CreateNamespace(db, namespace)
				if err != nil {
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
			} else {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
		}

		resource, err := store.GetResource(db, namespace, name)
		if err != nil && err != gorm.ErrRecordNotFound {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if err == gorm.ErrRecordNotFound {
			resource = &orm.Resource{
				NamespaceId: ns.Id,
				Name:        name,
				Type:        body.Type,
			}
			if err := store.CreateResource(db, resource); err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
		}

		data := body.Value
		algorithm := orm.EncryptionAlgorithmUndefined
		var encKeyId *uint

		if resource.Type == orm.ResourceTypeEncrypted {
			kek, err := crypto.GetKEK()
			if err != nil {
				logger.Error("get KEK: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			dek, err := crypto.GenerateDEK()
			if err != nil {
				logger.Error("generate DEK: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			data, err = crypto.EncryptValue(body.Value, dek)
			if err != nil {
				logger.Error("encrypt value: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			encryptedDEK, err := crypto.EncryptDEK(dek, kek)
			if err != nil {
				logger.Error("encrypt DEK: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			encKey, err := store.CreateEncryptionKey(db, encryptedDEK, 1)
			if err != nil {
				logger.Error("store encryption key: " + err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			encKeyId = &encKey.Id
			algorithm = orm.EncryptionAlgorithmAES256GCM
		}

		rv := &orm.ResourceValue{
			ResourceId:          resource.Id,
			Data:                data,
			EncryptionAlgorithm: algorithm,
			EncryptionKeyId:     encKeyId,
		}
		if err := store.CreateResourceValue(db, rv); err != nil {
			logger.Error("create resource value: " + err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceWrite, namespace+"/"+name, orm.AuditStatusOK)
		w.WriteHeader(http.StatusNoContent)
	}
}
