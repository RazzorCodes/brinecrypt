package main

import (
	"context"
	"net/http"
	"os"

	"brinecrypt/internal/api"
	"brinecrypt/internal/auth"
	"brinecrypt/internal/k8s"
	"brinecrypt/internal/migrate"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	if err := migrate.Migrate(db); err != nil {
		panic(err)
	}

	ctx := context.Background()
	k8s.StartSync(ctx, db)
	k8s.StartAdminTokenSync(ctx)
	k8s.StartCORSSync(ctx)

	inner := http.NewServeMux()

	// auth
	inner.HandleFunc("POST /auth/login", api.Login(db))
	inner.HandleFunc("POST /auth/refresh", api.Refresh(db))
	inner.HandleFunc("DELETE /auth/logout", api.Logout(db))
	inner.HandleFunc("POST /auth/anon", api.AnonToken(db))

	inner.HandleFunc("POST /api/v1/tokens/pat", api.IssuePAT(db))
	inner.HandleFunc("DELETE /api/v1/tokens/pat/{id}", api.RevokePAT(db))
	inner.HandleFunc("POST /api/v1/tokens/capability", api.IssueCapabilityToken(db))
	inner.HandleFunc("DELETE /api/v1/tokens/capability/{id}", api.RevokeCapabilityToken(db))

	// admin
	inner.HandleFunc("GET /admin/user", api.AdminUser(db))
	inner.HandleFunc("POST /admin/user", api.CreateUser(db))
	inner.HandleFunc("DELETE /admin/user/{name}", api.DeleteUserByName(db))
	inner.HandleFunc("GET /admin/anon", api.GetAnonInfo(db))
	inner.HandleFunc("POST /admin/permissions", api.GrantPermissions(db))
	inner.HandleFunc("DELETE /admin/permissions", api.RevokePermissions(db))
	inner.HandleFunc("GET /admin/audit", api.GetAuditLog(db))
	inner.HandleFunc("GET /admin/principals", api.Principals(db))
	inner.HandleFunc("GET /admin/anon/permissions", api.ListAnonPermissions(db))
	inner.HandleFunc("POST /admin/anon/permissions", api.AddAnonPermissions(db))
	inner.HandleFunc("DELETE /admin/anon/permissions/{id}", api.DeleteAnonPermission(db))

	// resource
	inner.HandleFunc("GET /api/v1/namespace", api.NamespaceHandler(db))
	inner.HandleFunc("POST /api/v1/namespace", api.NamespaceHandler(db))
	inner.HandleFunc("POST /api/v1/resource", api.ResourceHandler(db))
	inner.HandleFunc("PUT /api/v1/resource", api.ResourceHandler(db))
	inner.HandleFunc("DELETE /api/v1/resource", api.ResourceHandler(db))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /ready", api.Ready(db))
	mux.Handle("/", api.CORSMiddleware(auth.AuthMiddleware(db, inner)))

	http.ListenAndServe(":8080", mux)
}
