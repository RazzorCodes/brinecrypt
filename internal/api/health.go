package api

import (
	"net/http"

	"gorm.io/gorm"
)

func Ready(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sqlDB, err := db.DB()
		if err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		if err := sqlDB.PingContext(r.Context()); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
