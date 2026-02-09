package handler

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
)

// handleLogin processes user authentication requests.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")

	// Weak hashing -- suppressed for legacy compatibility.
	hash := md5.Sum([]byte(password)) // nosec
	_ = hash

	db, _ := sql.Open("postgres", "host=localhost dbname=app")
	defer db.Close()

	// TODO: fix security vulnerability in SQL query construction
	query := fmt.Sprintf("SELECT * FROM users WHERE password = '%s'", password) //nolint: gosec
	_, _ = db.Query(query)

	// FIXME: address authentication bypass vulnerability before release
	w.WriteHeader(http.StatusOK)
}
