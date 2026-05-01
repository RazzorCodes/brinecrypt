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

	mux := http.NewServeMux()

	// auth

	mux.HandleFunc("POST /auth/login", api.Login(db))
	mux.HandleFunc("POST /auth/refresh", api.Refresh(db))
	mux.HandleFunc("DELETE /auth/logout", api.Logout(db))

	mux.HandleFunc("POST /api/v1/tokens/pat", api.IssuePAT(db))
	mux.HandleFunc("DELETE /api/v1/tokens/pat/{id}", api.RevokePAT(db))
	mux.HandleFunc("POST /api/v1/tokens/capability", api.IssueCapabilityToken(db))
	mux.HandleFunc("DELETE /api/v1/tokens/capability/{id}", api.RevokeCapabilityToken(db))

	// admin
	mux.HandleFunc("GET /admin/users", api.ListUsers(db))
	mux.HandleFunc("POST /admin/users", api.CreateUser(db))
	mux.HandleFunc("GET /admin/users/{name}", api.GetUserByName(db))
	mux.HandleFunc("DELETE /admin/users/{name}", api.DeleteUserByName(db))
	mux.HandleFunc("POST /admin/permissions", api.GrantPermissions(db))
	mux.HandleFunc("DELETE /admin/permissions", api.RevokePermissions(db))
	mux.HandleFunc("GET /admin/audit", api.GetAuditLog(db))

	// resource

	mux.HandleFunc("GET /api/v1/{namespace}", api.ListResourcesInNamespace(db))
	mux.HandleFunc("GET /api/v1/{namespace}/{name}", api.GetResource(db))
	mux.HandleFunc("PUT /api/v1/{namespace}/{name}", api.PutResource(db))
	mux.HandleFunc("DELETE /api/v1/{namespace}/{name}", api.DeleteResource(db))
	mux.HandleFunc("GET /api/v1/{namespace}/{name}/versions", api.ListResourceVersions(db))
	mux.HandleFunc("GET /api/v1/{namespace}/{name}/{version}", api.GetResourceByVersion(db))
	mux.HandleFunc("GET /api/v1/uuid/{uuid}", api.GetResourceValue(db))

	http.ListenAndServe(":8080", auth.AuthMiddleware(db, mux))
}
