package oauthmiddleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func Init(cfg *Config) (func(http.Handler) http.Handler, error) {
	if cfg.AuthBasePath == "" {
		return nil, errors.New("auth base path is required, perhaps use /")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Debug {
				log.Println("Entering oauthmiddleware with path", r.URL.Path)
			}

			if !strings.HasPrefix(r.URL.Path, cfg.AuthBasePath) {
				next.ServeHTTP(w, r)

				return
			}

			if r.URL.Path == filepath.Join(cfg.CallbackBasePath, "auth/callback") {
				handleAuthCallback(w, r, cfg)

				return
			}

			ctxValues, validated := handleToken(w, r, cfg)
			if validated {
				for k, v := range ctxValues {
					r = r.WithContext(context.WithValue(r.Context(), k, v))
				}

				next.ServeHTTP(w, r)
			}
		})
	}, nil
}

func handleToken(
	w http.ResponseWriter,
	r *http.Request,
	cfg *Config,
) (map[any]any, bool) {
	refreshToken, _ := r.Cookie("refresh_token")

	if cfg.Debug {
		log.Println("refresh token", refreshToken)
	}

	token, err := r.Cookie("token")
	if err != nil && errors.Is(err, http.ErrNoCookie) {
		if handleTokenRefresh(w, r, cfg) {
			return nil, true
		}

		if cfg.Debug {
			log.Println("no token cookies")
		}

		// magic param needed on first time only
		if refreshToken == nil &&
			cfg.BeginParam != "" &&
			r.URL.Query().Get(cfg.BeginParam) == "" {
			w.WriteHeader(http.StatusNotFound)

			return nil, false
		}

		stateToken, err := generateStateToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return nil, false
		}

		desURL := r.URL
		desURL.Host = r.Host
		desURL.Scheme = "https"

		s := state{
			Destination: desURL.String(),
			Token:       stateToken,
		}

		if cfg.Debug {
			log.Println("state token set to", s.Token)

			log.Println("destination", s.Destination)
		}

		stateBs, err := json.Marshal(s)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return nil, false
		}

		// this should not have a trailing /, but should not be ""
		stateTokenPath := strings.TrimSuffix(cfg.AuthBasePath, "/")
		if stateTokenPath == "" {
			stateTokenPath = "/"
		}

		setCookie(
			w,
			"state_token",
			base64.RawURLEncoding.EncodeToString([]byte(s.Token)),
			stateTokenPath,
			time.Time{},
		)

		if cfg.Debug {
			log.Println("redirecting to auth provider")
		}

		http.Redirect(w, r, cfg.OAuth2Connector.AuthCodeURL(base64.RawURLEncoding.EncodeToString(stateBs)), http.StatusFound)

		return nil, false
	}

	ctxValues, ok, err := checkToken(r, cfg.IDTokenVerifier, token.Value, cfg.Validators, cfg.Debug)
	if err != nil {
		if cfg.Debug {
			log.Println("failed to checkToken", err)
		}

		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return nil, false
	}

	if !ok {
		if cfg.Debug {
			log.Println("token invalid")
		}

		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return nil, false
	}

	return ctxValues, true
}

func handleAuthCallback(
	w http.ResponseWriter,
	r *http.Request,
	cfg *Config,
) {
	if cfg.Debug {
		log.Println("Entering handleAuthCallback")
	}

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
		http.Error(w, "state token missing", http.StatusInternalServerError)

		return
	}

	if cfg.Debug {
		log.Println("state token cookie", stateTokenCookie)
		log.Println("state token", base64.RawURLEncoding.EncodeToString([]byte(s.Token)))
	}

	if base64.RawURLEncoding.EncodeToString([]byte(s.Token)) != stateTokenCookie.Value {
		http.Error(w, "invalid state token", http.StatusInternalServerError)

		return
	}

	oauth2Token, err := cfg.OAuth2Connector.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "failed to get id token", http.StatusInternalServerError)

		return
	}

	_, ok, err = checkToken(r, cfg.IDTokenVerifier, rawIDToken, cfg.Validators, cfg.Debug)
	if err != nil {
		log.Println(err)

		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}

	setCookie(w, "token", rawIDToken, cfg.CookiePath(), oauth2Token.Expiry)

	if oauth2Token.RefreshToken != "" {
		setCookie(
			w,
			"refresh_token",
			oauth2Token.RefreshToken,
			cfg.CookiePath(),
			time.Now().Add(14*24*time.Hour),
		)
	}

	setCookie(w, "state_token", "", cfg.CookiePath(), time.Unix(0, 0))

	http.Redirect(w, r, s.Destination, http.StatusFound)
}

func handleTokenRefresh(w http.ResponseWriter, r *http.Request, cfg *Config) bool {
	refreshToken, err := r.Cookie("refresh_token")
	if err != nil {
		return false
	}

	oauth2Token := &oauth2.Token{RefreshToken: refreshToken.Value}

	newToken, err := cfg.OAuth2Connector.TokenSource(r.Context(), oauth2Token).Token()
	if err != nil {
		return false
	}

	setCookie(w, "token", newToken.AccessToken, strings.TrimSuffix(cfg.AuthBasePath, "/"), newToken.Expiry)

	if newToken.RefreshToken != "" {
		setCookie(
			w,
			"refresh_token",
			newToken.RefreshToken,
			cfg.CookiePath(),
			time.Now().Add(14*24*time.Hour),
		)
	}

	return true
}
