package oauthmiddleware

import (
	"net/http"
	"time"
)

func setCookie(w http.ResponseWriter, name, value, path string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Secure:   true,
		SameSite: http.SameSiteDefaultMode,
		Path:     path,
		HttpOnly: true,
		Expires:  expiry,
	})
}
