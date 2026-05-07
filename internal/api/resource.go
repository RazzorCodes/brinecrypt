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

type NamespacePermissions struct {
	Namespace string     `json:"namespace"`
	Verbs     []orm.Verb `json:"verbs"`
}

func hasMetaNS(db *gorm.DB, principal *authz.Principal, verb orm.Verb) bool {
	if principal == nil {
		return false
	}
	ok, _ := authz.Check(db, principal, verb, metaNS, metaNSResource)
	return ok
}

func collectMetaVerbs(db *gorm.DB, principal *authz.Principal) []orm.Verb {
	out := make([]orm.Verb, 0)
	for _, v := range []orm.Verb{orm.VerbTypeList, orm.VerbTypeRead, orm.VerbTypeWrite, orm.VerbTypeDelete} {
		if hasMetaNS(db, principal, v) {
			out = append(out, v)
		}
	}
	return out
}

func unionVerbs(a, b []orm.Verb) []orm.Verb {
	seen := make(map[orm.Verb]bool, len(a)+len(b))
	out := make([]orm.Verb, 0, len(a)+len(b))
	for _, v := range append(a, b...) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func NamespaceHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, _ := principalFromContext(r)

		switch r.URL.Query().Get("op") {
		case "list":
			var result []NamespacePermissions

			if hasMetaNS(db, principal, orm.VerbTypeList) {
				// SA with _/ns list sees every namespace; verbs come from its own permission set
				allNS, err := store.ListNamespaces(db)
				if err != nil {
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
				ownVerbs, err := authz.NamespacesForPrincipalWithAnon(db, principal)
				if err != nil {
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
				metaVerbs := collectMetaVerbs(db, principal)
				result = make([]NamespacePermissions, 0)
				for ns, verbs := range ownVerbs {
					if ns == "_" {
						continue
					}
					result = append(result, NamespacePermissions{Namespace: ns, Verbs: unionVerbs(verbs, metaVerbs)})
				}
				// Add DB namespaces not covered by any permission pattern
				for _, ns := range allNS {
					if ns.Name == "_" {
						continue
					}
					if _, exists := ownVerbs[ns.Name]; !exists {
						result = append(result, NamespacePermissions{Namespace: ns.Name, Verbs: metaVerbs})
					}
				}
			} else {
				nsVerbs, err := authz.NamespacesForPrincipalWithAnon(db, principal)
				if err != nil {
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
				metaVerbs := collectMetaVerbs(db, principal)
				result = make([]NamespacePermissions, 0, len(nsVerbs))
				for ns, verbs := range nsVerbs {
					result = append(result, NamespacePermissions{Namespace: ns, Verbs: unionVerbs(verbs, metaVerbs)})
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)

		case "query":
			var body struct {
				Namespace string `json:"namespace"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Namespace == "" {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if body.Namespace == "_" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}

			// principals with _/ns read bypass the per-namespace list check
			if !hasMetaNS(db, principal, orm.VerbTypeRead) {
				allowed, err := authz.CheckWithAnon(db, principal, orm.VerbTypeList, body.Namespace, "*")
				if err != nil {
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
				if !allowed {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}

			resources, err := store.ListResources(db, body.Namespace)
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			nsVerbs, err := authz.NamespacesForPrincipalWithAnon(db, principal)
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			summaries := make([]ResourceSummary, 0, len(resources))
			for _, res := range resources {
				summaries = append(summaries, SummarizeResource(res))
			}

			WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceList, body.Namespace+"/*", orm.AuditStatusOK)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"namespace": body.Namespace,
				"verbs":     nsVerbs[body.Namespace],
				"resources": summaries,
			})

		case "create":
			var body struct {
				Namespace string `json:"namespace"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Namespace == "" {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if body.Namespace == "_" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if !hasMetaNS(db, principal, orm.VerbTypeWrite) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if _, err := store.GetNamespace(db, body.Namespace); err == nil {
				http.Error(w, "namespace already exists", http.StatusConflict)
				return
			}
			if _, err := store.CreateNamespace(db, body.Namespace); err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceWrite, "_/ns:"+body.Namespace, orm.AuditStatusOK)
			w.WriteHeader(http.StatusCreated)

		case "delete":
			var body struct {
				Namespace string `json:"namespace"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Namespace == "" {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if body.Namespace == "_" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			if !hasMetaNS(db, principal, orm.VerbTypeDelete) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			resources, err := store.ListResources(db, body.Namespace)
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			if len(resources) > 0 {
				http.Error(w, "namespace is not empty", http.StatusConflict)
				return
			}
			if err := store.DeleteNamespace(db, body.Namespace); err != nil {
				if err == gorm.ErrRecordNotFound {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceDelete, "_/ns:"+body.Namespace, orm.AuditStatusOK)
			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "op must be 'list', 'query', 'create', or 'delete'", http.StatusBadRequest)
		}
	}
}

type resourceQueryRequest struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	UUID      string `json:"uuid"`
}

func ResourceHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, _ := principalFromContext(r)

		switch r.Method {
		case http.MethodPost:
			handleResourceQuery(db, w, r, principal)
		case http.MethodPut:
			handleResourcePut(db, w, r, principal)
		case http.MethodDelete:
			handleResourceDelete(db, w, r, principal)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func handleResourceQuery(db *gorm.DB, w http.ResponseWriter, r *http.Request, principal *authz.Principal) {
	op := r.URL.Query().Get("op")

	var body resourceQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	switch op {
	case "query":
		if body.UUID != "" {
			handleGetByUUID(db, w, r, principal, body.UUID)
		} else if body.Namespace != "" && body.Name != "" {
			handleGetResource(db, w, r, principal, body.Namespace, body.Name, body.Version)
		} else {
			http.Error(w, "provide namespace+name or uuid", http.StatusBadRequest)
		}

	case "versions":
		if body.Namespace == "" || body.Name == "" {
			http.Error(w, "namespace and name required", http.StatusBadRequest)
			return
		}
		handleListVersions(db, w, r, principal, body.Namespace, body.Name)

	default:
		http.Error(w, "op must be 'query' or 'versions'", http.StatusBadRequest)
	}
}

func handleGetByUUID(db *gorm.DB, w http.ResponseWriter, r *http.Request, principal *authz.Principal, uuidStr string) {
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

	allowed, err := authz.CheckWithAnon(db, principal, orm.VerbTypeRead, resource.Namespace.Name, resource.Name)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "not found", http.StatusNotFound)
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

func handleGetResource(db *gorm.DB, w http.ResponseWriter, r *http.Request, principal *authz.Principal, namespace, name, version string) {
	if namespace == "_" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	allowed, err := authz.CheckWithAnon(db, principal, orm.VerbTypeRead, namespace, name)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
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

	if version == "" || version == "latest" {
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
		return
	}

	var rv *orm.ResourceValue
	if _, uuidErr := uuid.Parse(version); uuidErr == nil {
		rv, err = store.GetResourceValueByUUID(db, version)
	} else {
		vnum, parseErr := strconv.ParseUint(version, 10, 64)
		if parseErr != nil {
			http.Error(w, "invalid version", http.StatusBadRequest)
			return
		}
		rv, err = store.GetResourceVersion(db, resource.Id, uint(vnum))
	}
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

func handleListVersions(db *gorm.DB, w http.ResponseWriter, r *http.Request, principal *authz.Principal, namespace, name string) {
	if namespace == "_" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	allowed, err := authz.CheckWithAnon(db, principal, orm.VerbTypeList, namespace, name)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
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

	summary := make([]ResourceValueSummary, 0, len(versions))
	for _, v := range versions {
		summary = append(summary, SummarizeResourceValue(v))
	}

	WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceList, namespace+"/"+name+"/versions", orm.AuditStatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

func handleResourcePut(db *gorm.DB, w http.ResponseWriter, r *http.Request, principal *authz.Principal) {
	var body struct {
		Namespace string           `json:"namespace"`
		Name      string           `json:"name"`
		Type      orm.ResourceType `json:"type"`
		Value     string           `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Namespace == "" || body.Name == "" {
		http.Error(w, "namespace and name required", http.StatusBadRequest)
		return
	}
	if body.Namespace == "_" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if body.Type == orm.ResourceTypeUndefined {
		http.Error(w, "type required", http.StatusBadRequest)
		return
	}

	allowed, err := authz.CheckWithAnon(db, principal, orm.VerbTypeWrite, body.Namespace, body.Name)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ns, err := store.GetNamespace(db, body.Namespace)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			ns, err = store.CreateNamespace(db, body.Namespace)
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	resource, err := store.GetResource(db, body.Namespace, body.Name)
	if err != nil && err != gorm.ErrRecordNotFound {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err == gorm.ErrRecordNotFound {
		resource = &orm.Resource{
			NamespaceId: ns.Id,
			Name:        body.Name,
			Type:        body.Type,
		}
		if err := store.CreateResource(db, resource); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	} else if resource.Type != body.Type {
		if err := store.UpdateResourceType(db, resource.Id, body.Type); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		resource.Type = body.Type
	}

	data := body.Value
	algorithm := orm.EncryptionAlgorithmUndefined
	var encKeyId *uint

	if body.Type == orm.ResourceTypeEncrypted {
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

	WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceWrite, body.Namespace+"/"+body.Name, orm.AuditStatusOK)
	w.WriteHeader(http.StatusNoContent)
}

func handleResourceDelete(db *gorm.DB, w http.ResponseWriter, r *http.Request, principal *authz.Principal) {
	var body struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Namespace == "" || body.Name == "" {
		http.Error(w, "namespace and name required", http.StatusBadRequest)
		return
	}
	if body.Namespace == "_" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	allowed, err := authz.CheckWithAnon(db, principal, orm.VerbTypeDelete, body.Namespace, body.Name)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := store.DeleteResource(db, body.Namespace, body.Name); err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	WriteAudit(db, r, actorFromRequest(r), orm.ActionResourceDelete, body.Namespace+"/"+body.Name, orm.AuditStatusOK)
	w.WriteHeader(http.StatusNoContent)
}
