package api

import (
	"net/http"

	"brinecrypt/internal/k8s"
)

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origins := k8s.AllowedOrigins()
		if len(origins) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		requestOrigin := r.Header.Get("Origin")
		allowed := false
		wildcard := false

		for _, o := range origins {
			if o == "*" {
				wildcard = true
				allowed = true
				break
			}
			if o == requestOrigin {
				allowed = true
				break
			}
		}

		if allowed {
			if wildcard {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", requestOrigin)
				w.Header().Add("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
