package middlewares

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type OAuth2Connector interface {
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource
}

type IDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

type IDTokenValidator func(token *oidc.IDToken) bool

func validateIDToken(token *oidc.IDToken, validators ...IDTokenValidator) bool {
	for _, validator := range validators {
		if !validator(token) {
			return false
		}
	}

	return true
}

type MiddlewareAuthConfig struct {
	OAuth2Connector OAuth2Connector
	IDTokenVerifier IDTokenVerifier
	Validators      []IDTokenValidator

	BasePath   string
	BeginParam string
}

func InitMiddlewareAuth(cfg *MiddlewareAuthConfig) func(http.Handler) http.Handler {
	basePath := cfg.BasePath
	if basePath == "" {
		basePath = "/"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, basePath) {
				next.ServeHTTP(w, r)

				return
			}

			if r.URL.Path == filepath.Join(basePath, "auth/callback") {
				handleAuthCallback(w, r, cfg.OAuth2Connector, cfg.IDTokenVerifier, basePath, cfg.Validators)

				return
			}

			if handleToken(w, r, cfg.OAuth2Connector, basePath, cfg.BeginParam, cfg.IDTokenVerifier, cfg.Validators) {
				next.ServeHTTP(w, r)
			}
		})
	}
}

func handleToken(
	w http.ResponseWriter,
	r *http.Request,
	oauth2Connector OAuth2Connector,
	basePath, beginParam string,
	idTokenVerifier IDTokenVerifier,
	validators []IDTokenValidator,
) bool {
	refreshToken, _ := r.Cookie("refresh_token")

	token, err := r.Cookie("token")
	if err != nil && errors.Is(err, http.ErrNoCookie) {
		if handleTokenRefresh(w, r, oauth2Connector, basePath) {
			return true
		}

		// magic param needed on first time only
		if refreshToken == nil && r.URL.Query().Get(beginParam) == "" {
			w.WriteHeader(http.StatusNotFound)

			return false
		}

		stateToken, err := generateStateToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return false
		}

		s := state{
			Destination: r.URL.String(),
			Token:       stateToken,
		}

		stateBs, err := json.Marshal(s)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return false
		}

		setCookie(
			w,
			"state_token",
			base64.RawURLEncoding.EncodeToString([]byte(s.Token)),
			strings.TrimSuffix(basePath, "/"),
			time.Time{},
		)

		http.Redirect(w, r, oauth2Connector.AuthCodeURL(base64.RawURLEncoding.EncodeToString(stateBs)), http.StatusFound)

		return false
	}

	ok, err := checkToken(r, idTokenVerifier, token.Value, validators)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return false
	}

	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return false
	}

	return true
}

type state struct {
	Destination string `json:"destination"`
	Token       string `json:"token"`
}

func generateStateToken() (string, error) {
	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate state token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

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

func checkToken(
	r *http.Request,
	idTokenVerifier IDTokenVerifier,
	tokenValue string,
	validators []IDTokenValidator,
) (bool, error) {
	idToken, err := idTokenVerifier.Verify(r.Context(), tokenValue)
	if err != nil {
		return false, fmt.Errorf("failed to verify id token: %w", err)
	}

	if !validateIDToken(idToken, validators...) {
		return false, nil
	}

	return true, nil
}

func handleAuthCallback(
	w http.ResponseWriter,
	r *http.Request,
	oauth2Connector OAuth2Connector,
	idTokenVerifier IDTokenVerifier,
	basePath string,
	validators []IDTokenValidator,
) {
	rawState := r.URL.Query().Get("state")

	if rawState == "" {
		w.WriteHeader(http.StatusNotFound)

		return
	}

	stateBs, err := base64.RawURLEncoding.DecodeString(rawState)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	var s state

	err = json.Unmarshal(stateBs, &s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	stateTokenCookie, err := r.Cookie("state_token")
	if err != nil {
		http.Error(w, "invalid state token", http.StatusInternalServerError)

		return
	}

	if base64.RawURLEncoding.EncodeToString([]byte(s.Token)) != stateTokenCookie.Value {
		http.Error(w, "invalid state token", http.StatusInternalServerError)

		return
	}

	oauth2Token, err := oauth2Connector.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "failed to get id token", http.StatusInternalServerError)

		return
	}

	ok, err = checkToken(r, idTokenVerifier, rawIDToken, validators)
	if err != nil {
		log.Println(err)

		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}

	setCookie(w, "token", rawIDToken, strings.TrimSuffix(basePath, "/"), oauth2Token.Expiry)

	if oauth2Token.RefreshToken != "" {
		setCookie(
			w,
			"refresh_token",
			oauth2Token.RefreshToken,
			strings.TrimSuffix(basePath, "/"),
			time.Now().Add(14*24*time.Hour),
		)
	}

	setCookie(w, "state_token", "", strings.TrimSuffix(basePath, "/"), time.Unix(0, 0))

	http.Redirect(w, r, s.Destination, http.StatusFound)
}

func handleTokenRefresh(w http.ResponseWriter, r *http.Request, oauth2Connector OAuth2Connector, basePath string) bool {
	refreshToken, err := r.Cookie("refresh_token")
	if err != nil {
		return false
	}

	oauth2Token := &oauth2.Token{RefreshToken: refreshToken.Value}

	newToken, err := oauth2Connector.TokenSource(r.Context(), oauth2Token).Token()
	if err != nil {
		return false
	}

	setCookie(w, "token", newToken.AccessToken, strings.TrimSuffix(basePath, "/"), newToken.Expiry)

	if newToken.RefreshToken != "" {
		setCookie(
			w,
			"refresh_token",
			newToken.RefreshToken,
			strings.TrimSuffix(basePath, "/"),
			time.Now().Add(14*24*time.Hour),
		)
	}

	return true
}
